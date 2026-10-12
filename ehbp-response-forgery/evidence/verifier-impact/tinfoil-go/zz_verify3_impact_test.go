package tinfoil

// LOCAL verification tests (loopback only) for candidate L3-ehbp-response-forgery.
// They reuse the helpers in zz_poc_ehbp_plaintext_test.go (intermediary-free
// variants are defined here) and the enclave.PoCHandleWithVerification hook,
// which replaces only the attestation fetch+verify step.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func v3Verified(hpkeKeyHex, repo string) func() (*verify.Verification, error) {
	return func() (*verify.Verification, error) {
		return &verify.Verification{
			ConfigRepo: repo,
			CryptoMaterial: []document.CryptoMaterialItem{
				{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
				{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: hpkeKeyHex},
			},
			FreshnessExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}
}

// statusServer answers every sealed POST with the given status and a plaintext
// completion body (no Ehbp-Response-Nonce), optionally with a Location header.
func statusServer(status int, location string, log *pocLog) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		log.add(r.Method + " " + r.URL.RequestURI() + " sealed=" + map[bool]string{true: "yes", false: "no"}[r.Header.Get("Ehbp-Encapsulated-Key") != ""] +
			" enclaveURL=" + r.Header.Get(enclaveURLHeader) + " model=" + r.Header.Get(modelHeader) +
			" plaintextLeak=" + map[bool]string{true: "YES", false: "no"}[bytes.Contains(body, []byte("secret prompt"))])
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, forgedCompletion)
	}))
}

// Which nonce-less statuses does the default EHBP client accept as a completion?
func TestVerify3_StatusMatrixDirect(t *testing.T) {
	enclaveID, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	cases := []struct {
		status   int
		location string
	}{
		{200, ""}, {201, ""}, {204, ""}, {300, ""}, {301, ""}, {302, ""}, {303, ""}, {305, ""}, {306, ""}, {399, ""}, {400, ""}, {500, ""},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status)+"_"+itoa(tc.status), func(t *testing.T) {
			log := &pocLog{}
			srv := statusServer(tc.status, tc.location, log)
			defer srv.Close()
			trustIntermediary(t, srv)
			c := pocClient(t, "enclave.example.com", enclaveID.MarshalPublicKeyHex(), "")
			resp, err := c.Chat.Completions.New(context.Background(), chatParams())
			for _, l := range log.all() {
				t.Logf("intermediary saw: %s", l)
			}
			if err != nil {
				t.Logf("status %d -> SDK error: %v", tc.status, err)
			} else {
				t.Logf("status %d -> SDK ACCEPTED completion content=%q", tc.status, resp.Choices[0].Message.Content)
			}
		})
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// Gateway mode: wire a Gateway exactly like NewGateway does, except the replica
// handle's attestation step is replaced via the PoC hook (ViaRelay only changes
// where attestation is fetched from, which the hook replaces anyway).
func gatewayForPoC(t *testing.T, baseURL, model, replicaHost, hpkeKeyHex string) *Gateway {
	policy, err := newGatewayPolicy(GatewayOptions{}, enclave.Options{})
	require.NoError(t, err)
	seal := &sealTransport{
		catalog: func() Catalog {
			return Catalog{model: {Repo: "tinfoilsh/confidential-llama3-3-70b", Hosts: []string{replicaHost}}}
		},
		policy: policy,
		secret: "poc-user-cache-secret",
		build: func(r replica) (http.RoundTripper, error) {
			secure, err := enclave.PoCHandleWithVerification(r.host, r.ref, v3Verified(hpkeKeyHex, r.ref))
			if err != nil {
				return nil, err
			}
			httpClient, err := ehbpHTTPClient(secure, r.host, baseURL)
			if err != nil {
				return nil, err
			}
			return &verifiedReplicaTransport{
				recoveryTransport: &recoveryTransport{transport: httpClient.Transport},
				verification:      secure.Verification,
			}, nil
		},
	}
	httpClient, err := boundHTTPClient(&http.Client{Transport: seal}, "", baseURL, "")
	require.NoError(t, err)
	oc := openai.NewClient(option.WithHTTPClient(httpClient), option.WithBaseURL(baseURL),
		option.WithAPIKey("sk-poc"), option.WithMaxRetries(0))
	return &Gateway{Client: &oc, httpClient: httpClient, seal: seal}
}

func TestVerify3_GatewayMode(t *testing.T) {
	enclaveID, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	honestEnclave := enclaveID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, strings.Replace(forgedCompletion, "FORGED BY INTERMEDIARY", "REAL ENCLAVE ANSWER", 1))
	}))
	for _, mode := range []string{"honest", "control-200", "status-300", "redirect-303"} {
		t.Run(mode, func(t *testing.T) {
			log := &pocLog{}
			srv := intermediary(t, mode, honestEnclave, log)
			defer srv.Close()
			trustIntermediary(t, srv)
			g := gatewayForPoC(t, "https://gateway.example.com/v1/", "llama3-3-70b", "replica.example.com", enclaveID.MarshalPublicKeyHex())
			resp, err := g.Chat.Completions.New(context.Background(), chatParams())
			for _, l := range log.all() {
				t.Logf("gateway saw: %s", l)
			}
			if err != nil {
				t.Logf("GATEWAY RESULT: SDK error: %v", err)
			} else {
				t.Logf("GATEWAY RESULT: SDK returned completion content=%q", resp.Choices[0].Message.Content)
			}
		})
	}
}

// Escape hatch: client.HTTPClient() used for a raw JSON POST by a caller that
// checks for 200. The 303 path converts the sealed POST into an unsealed GET.
func TestVerify3_HTTPClientEscapeHatch303(t *testing.T) {
	enclaveID, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	log := &pocLog{}
	srv := intermediary(t, "redirect-303", nil, log)
	defer srv.Close()
	trustIntermediary(t, srv)
	c := pocClient(t, "enclave.example.com", enclaveID.MarshalPublicKeyHex(), "")
	resp, err := c.HTTPClient().Post("https://enclave.example.com/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"my secret prompt"}]}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, l := range log.all() {
		t.Logf("intermediary saw: %s", l)
	}
	t.Logf("HTTPClient() result: status=%d nonce=%q body=%s", resp.StatusCode, resp.Header.Get("Ehbp-Response-Nonce"), b)
}

// Negative control: TLS-pinning mode with the same intermediary fails closed.
func TestVerify3_TLSModeControl(t *testing.T) {
	enclaveID, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	for _, mode := range []string{"status-300", "redirect-303"} {
		t.Run(mode, func(t *testing.T) {
			log := &pocLog{}
			srv := intermediary(t, mode, nil, log)
			defer srv.Close()
			trustIntermediary(t, srv)
			handle, err := enclave.PoCHandleWithVerification("enclave.example.com", "tinfoilsh/confidential-model-router",
				v3Verified(enclaveID.MarshalPublicKeyHex(), "tinfoilsh/confidential-model-router"))
			require.NoError(t, err)
			c, err := createClientFromHandle(handle, TransportTLS, "", "poc-user-cache-secret",
				option.WithAPIKey("sk-poc"), option.WithMaxRetries(0))
			require.NoError(t, err)
			_, err = c.Chat.Completions.New(context.Background(), chatParams())
			t.Logf("TLS mode %s -> err=%v (intermediary requests seen: %d)", mode, err, len(log.all()))
			require.Error(t, err)
		})
	}
}
