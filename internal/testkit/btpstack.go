// Package testkit holds test fixtures shared by btpingo's own tests and
// ginpingo's tests. It is importable only from inside this module
// (internal/), so it is not part of the public API — it exists purely
// to avoid duplicating large HTTP-stack fixtures across the two test
// suites.
package testkit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hochfrequenz/btpingo"
)

// BTPStack spins up three httptest servers standing in for XSUAA, the
// Destination service, and the on-premise proxy. It is deliberately
// coarse-grained: the package's value is the wiring between these
// three, so the tests verify the wiring end-to-end rather than mock
// individual helpers.
type BTPStack struct {
	XSUAA  *httptest.Server
	Dest   *httptest.Server
	Proxy  *httptest.Server
	OnPrem *httptest.Server
	Env    *btpingo.Env

	Tokens  atomic.Int32 // exchange count on the XSUAA server
	Lookups atomic.Int32 // destination lookups
	Calls   atomic.Int32 // on-prem calls

	// StrayCalls counts proxy requests (CONNECT included) for any
	// origin other than RedirectDest. Only meaningful on NewRedirectStack.
	StrayCalls atomic.Int32
}

// RedirectDest is the destination origin of NewRedirectStack. The fake
// proxy forwards by path only, so the host need not resolve.
const RedirectDest = "http://sap.example:8000"

// NewBTPStack builds a BTPStack whose Destination-service response body
// is destBody.
func NewBTPStack(t testing.TB, destBody string) *BTPStack {
	t.Helper()
	s := &BTPStack{}

	// On-prem "SAP". The test proxy below forwards to here.
	s.OnPrem = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Calls.Add(1)
		// /redirect-chain-1 .. -9 redirect to the next link of the chain.
		if n, ok := strings.CutPrefix(r.URL.Path, "/redirect-chain-"); ok {
			if i, err := strconv.Atoi(n); err == nil && i < 10 {
				http.Redirect(w, r, fmt.Sprintf("/redirect-chain-%d", i+1), http.StatusFound)
				return
			}
		}
		// Fixed paths that answer with a redirect, for the redirect tests.
		switch r.URL.Path {
		case "/redirect-off-host":
			http.Redirect(w, r, "http://elsewhere.example/landed", http.StatusFound)
			return
		case "/redirect-other-scheme":
			http.Redirect(w, r, "https://sap.example:8000/landed", http.StatusFound)
			return
		case "/redirect-other-port":
			http.Redirect(w, r, "http://sap.example:9000/landed", http.StatusFound)
			return
		case "/redirect-same-host":
			http.Redirect(w, r, "/landed", http.StatusFound)
			return
		case "/redirect-host-case":
			http.Redirect(w, r, "http://SAP.Example:8000/landed", http.StatusFound)
			return
		case "/redirect-chain-10":
			// The 10th redirect of a chain leaves the origin.
			http.Redirect(w, r, "http://elsewhere.example/landed", http.StatusFound)
			return
		case "/redirect-loop":
			http.Redirect(w, r, "/redirect-loop", http.StatusFound)
			return
		}
		// Echo back headers that the test wants to inspect.
		w.Header().Set("X-Received-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Received-UA", r.Header.Get("User-Agent"))
		w.Header().Set("X-Received-Location", r.Header.Get("SAP-Connectivity-SCC-Location_ID"))
		w.Header().Set("X-Received-Cookie", r.Header.Get("Cookie"))
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(struct {
			OK   bool   `json:"ok"`
			Path string `json:"path"`
		}{true, r.URL.Path})
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.OnPrem.Close)

	// Fake CC HTTP proxy: forward the incoming request to the onPrem URL,
	// asserting Proxy-Authorization along the way.
	s.Proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Proxy-Authorization"), "Bearer ") {
			http.Error(w, "missing proxy auth", http.StatusProxyAuthRequired)
			return
		}
		// The client sends an absolute URL for HTTP-through-HTTP-proxy.
		u, err := url.Parse(r.RequestURI)
		if r.Method == http.MethodConnect || err != nil || !strings.EqualFold(u.Scheme+"://"+u.Host, RedirectDest) {
			s.StrayCalls.Add(1)
		}
		if err != nil || u.Host == "" {
			http.Error(w, "bad request-uri", http.StatusBadRequest)
			return
		}
		onPremURL, _ := url.Parse(s.OnPrem.URL)
		outReq, _ := http.NewRequestWithContext(r.Context(), r.Method, onPremURL.String()+u.Path, r.Body)
		for k, vs := range r.Header {
			if strings.EqualFold(k, "Proxy-Authorization") {
				continue
			}
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		// Relay a redirect to the client instead of following it here:
		// the redirect tests are about the Service's client.
		relay := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := relay.Do(outReq)
		if err != nil {
			http.Error(w, "fake proxy: relay failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(s.Proxy.Close)

	// Destination service — returns the caller-supplied body.
	s.Dest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Lookups.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(destBody))
	}))
	t.Cleanup(s.Dest.Close)

	// XSUAA token endpoint — returns a one-hour token per call.
	s.XSUAA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := s.Tokens.Add(1)
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"bearer","expires_in":3600}`, n)
	}))
	t.Cleanup(s.XSUAA.Close)

	proxyURL, _ := url.Parse(s.Proxy.URL)
	s.Env = &btpingo.Env{
		XSUAA: &btpingo.XSUAACredentials{URL: s.XSUAA.URL, ClientID: "x", ClientSecret: "y", XSAppName: "GoApp", UAADomain: "uaa"},
		Dest:  &btpingo.DestCredentials{URI: s.Dest.URL, ClientID: "d", ClientSecret: "ds", URL: s.XSUAA.URL},
		Conn:  &btpingo.ConnCredentials{ClientID: "c", ClientSecret: "cs", URL: s.XSUAA.URL, OnPremiseProxyHost: proxyURL.Hostname(), OnPremiseProxyPort: proxyURL.Port()},
	}
	return s
}

// NewRedirectStack returns a BTPStack whose destination is RedirectDest.
func NewRedirectStack(t testing.TB) *BTPStack {
	t.Helper()
	return NewBTPStack(t, fmt.Sprintf(`{"destinationConfiguration":{"Name":"D","URL":%q,"ProxyType":"OnPremise","Authentication":"NoAuthentication"}}`, RedirectDest))
}
