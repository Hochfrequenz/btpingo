package btpingo

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
)

// This is an internal test so it can reach into the unexported
// onPremiseRoundTripper and its base Transport to exercise the
// GetProxyConnectHeader closure directly. The closure fires on the
// HTTPS CONNECT-tunnel path, which is hard to observe via httptest
// without standing up a full CONNECT-aware proxy plus a trusted
// TLS cert chain; direct invocation is cheaper and tighter.

// Test_NewOnPremiseTransport_GetProxyConnectHeader_ReturnsBearer
// pins the happy path: the closure calls the provider with the
// ambient request context and returns a Proxy-Authorization header
// carrying the fetched token.
func Test_NewOnPremiseTransport_GetProxyConnectHeader_ReturnsBearer(t *testing.T) {
	var gotCtx context.Context
	rt, err := NewOnPremiseTransport(
		&ConnCredentials{OnPremiseProxyHost: "proxy.invalid", OnPremiseProxyPort: "8081"},
		func(req *http.Request) (string, error) {
			gotCtx = req.Context()
			return "connect-token", nil
		},
	)
	then.AssertThat(t, err, is.Nil())

	inner := rt.(*onPremiseRoundTripper)
	then.AssertThat(t, inner.base.GetProxyConnectHeader != nil, is.True())

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "sentinel")
	hdr, err := inner.base.GetProxyConnectHeader(ctx, nil, "sap.internal:443")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, hdr.Get("Proxy-Authorization"), is.EqualTo("Bearer connect-token"))

	// Provider was invoked with a request that carries our context —
	// that means ctx.Done() from the outer call propagates into the
	// token fetch, which is the whole reason we plumb ctx here.
	sentinel, _ := gotCtx.Value(ctxKey{}).(string)
	then.AssertThat(t, sentinel, is.EqualTo("sentinel"))
}

// Test_NewOnPremiseTransport_GetProxyConnectHeader_PropagatesErr
// covers the failure branch: if the token provider errors, the
// closure must surface it so net/http aborts the CONNECT dial
// instead of attempting an un-authenticated tunnel.
func Test_NewOnPremiseTransport_GetProxyConnectHeader_PropagatesErr(t *testing.T) {
	rt, err := NewOnPremiseTransport(
		&ConnCredentials{OnPremiseProxyHost: "proxy.invalid", OnPremiseProxyPort: "8081"},
		func(*http.Request) (string, error) { return "", errors.New("xsuaa down") },
	)
	then.AssertThat(t, err, is.Nil())

	inner := rt.(*onPremiseRoundTripper)
	_, err = inner.base.GetProxyConnectHeader(context.Background(), nil, "sap.internal:443")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

// Test_RoundTrip_HTTPS_DoesNotLeakProxyAuthorizationToOrigin is an
// end-to-end regression test for the header-leak this package's HTTPS
// path used to have: RoundTrip set Proxy-Authorization on every request,
// including HTTPS ones, and that request travels inside the CONNECT
// tunnel — so the SAP origin, not just the proxy, received the
// Connectivity token. This stands up a minimal CONNECT-aware proxy plus
// a TLS origin to prove the header now stops at the tunnel: the CONNECT
// itself carries it, but the tunneled request does not.
func Test_RoundTrip_HTTPS_DoesNotLeakProxyAuthorizationToOrigin(t *testing.T) {
	var gotOriginAuth, gotConnectAuth string

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOriginAuth = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}
		gotConnectAuth = r.Header.Get("Proxy-Authorization")

		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = upstream.Close() }()
		w.WriteHeader(http.StatusOK)

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = client.Close() }()
		// Closing both conns on handler exit unblocks whichever io.Copy
		// direction is still waiting on the other, so the goroutine
		// below always ends instead of leaking past the test.
		go func() { _, _ = io.Copy(upstream, client) }()
		_, _ = io.Copy(client, upstream)
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	then.AssertThat(t, err, is.Nil())
	host, port, err := net.SplitHostPort(proxyURL.Host)
	then.AssertThat(t, err, is.Nil())

	rt, err := NewOnPremiseTransport(
		&ConnCredentials{OnPremiseProxyHost: host, OnPremiseProxyPort: port},
		func(*http.Request) (string, error) { return "conn-token", nil },
	)
	then.AssertThat(t, err, is.Nil())

	inner := rt.(*onPremiseRoundTripper)
	inner.base.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig

	req, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	then.AssertThat(t, err, is.Nil())
	// A caller-supplied Proxy-Authorization must not survive to the
	// origin either — RoundTrip has to strip it, not just refrain from
	// setting its own, exercising the r.Header.Del path below.
	req.Header.Set("Proxy-Authorization", "Bearer caller-supplied")
	resp, err := rt.RoundTrip(req)
	then.AssertThat(t, err, is.Nil())
	_ = resp.Body.Close()

	then.AssertThat(t, gotConnectAuth, is.EqualTo("Bearer conn-token"))
	then.AssertThat(t, gotOriginAuth, is.EqualTo(""))
	then.AssertThat(t, strings.HasPrefix(origin.URL, "https://"), is.True())
}
