// poc-websearch wires the shipped confidential-websearch packages exactly as
// cmd/websearch-mcp/main.go does in real-provider mode, except for the three
// clients that can only be constructed against Tinfoil production services:
//
//   - the attested inference client used by safeguard.NewPromptInjectionClient
//     (replaced by a local classifier that flags every page containing the
//     phrase "HIDDEN INSTRUCTIONS", i.e. a perfect classifier for this PoC's
//     payload, and logs every call it receives);
//   - the PII enclave client (nil; the shipped fetch handler never consults it);
//   - the usage reporter (nil; the shipped handlers accept a nil reporter).
//
// The MCP server and tool handlers (internal/server), tools.Service including
// the Cloudflare top-500k skip (internal/tools), the Exa contents client
// (internal/fetch) and the Radar ranker (internal/domainrank) are the shipped
// code, unmodified. Exa and Cloudflare are reached through HTTPS_PROXY, which
// the PoC points at a loopback stand-in (poc/exastub).
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tinfoilsh/confidential-websearch/internal/config"
	"github.com/tinfoilsh/confidential-websearch/internal/domainrank"
	"github.com/tinfoilsh/confidential-websearch/internal/fetch"
	"github.com/tinfoilsh/confidential-websearch/internal/safeguard"
	"github.com/tinfoilsh/confidential-websearch/internal/search"
	"github.com/tinfoilsh/confidential-websearch/internal/server"
	"github.com/tinfoilsh/confidential-websearch/internal/tools"
)

type pocClassifier struct {
	mu    sync.Mutex
	calls int
}

func (c *pocClassifier) Check(_ context.Context, content string) (*safeguard.CheckResult, error) {
	c.mu.Lock()
	c.calls++
	n := c.calls
	c.mu.Unlock()
	violation := strings.Contains(content, "HIDDEN INSTRUCTIONS")
	log.Printf("[poc-websearch] safeguard classifier call #%d: violation=%v (%d bytes)", n, violation, len(content))
	return &safeguard.CheckResult{Violation: violation, Rationale: "poc classifier"}, nil
}

func main() {
	log.SetOutput(os.Stderr)
	cfg := config.Load()
	descriptions, err := config.LoadToolDescriptions()
	if err != nil {
		log.Fatal(err)
	}
	searcher, err := search.NewProvider(search.Config{ExaAPIKey: cfg.ExaAPIKey})
	if err != nil {
		log.Fatal(err)
	}
	fetcher := fetch.NewFetcher(cfg.ExaAPIKey)
	classifier := &pocClassifier{}
	var ranker domainrank.Ranker = domainrank.NopRanker{}
	if cfg.CloudflareAPIToken != "" {
		cfRanker, err := domainrank.NewCloudflareRanker(context.Background(), cfg.CloudflareAPIToken)
		if err != nil {
			log.Printf("[poc-websearch] domain ranker unavailable: %v", err)
		}
		if cfRanker != nil {
			go cfRanker.Run(context.Background())
			ranker = cfRanker
		}
	}
	for _, host := range []string{"github.com", "attacker-blog.example", "exfil.attacker.example"} {
		log.Printf("[poc-websearch] ranker.InTopBucket(%q) = %v", host, ranker.InTopBucket(host))
	}
	svc := tools.NewService(searcher, fetcher, classifier, nil, ranker)

	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server.NewMCPServer(svc, cfg, descriptions, nil, "poc", r)
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if len(body) > 600 {
			body = append(body[:600], []byte("...")...)
		}
		log.Printf("[poc-websearch] %s %s authorization=%q X-Tinfoil-Tool-Injection-Check=%q X-Tinfoil-Tool-PII-Check=%q body=%s",
			r.Method, r.URL.Path, maskBearer(r.Header.Get("Authorization")), r.Header.Get("X-Tinfoil-Tool-Injection-Check"), r.Header.Get("X-Tinfoil-Tool-PII-Check"), string(body))
		handler.ServeHTTP(w, r)
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", logged)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("OK")) })
	log.Printf("[poc-websearch] listening on %s (search: %s)", cfg.ListenAddr, searcher.Name())
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, mux))
}

func maskBearer(v string) string {
	if v == "" {
		return ""
	}
	if len(v) > 14 {
		return v[:14] + "..."
	}
	return v
}
