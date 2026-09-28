package btpingo

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// schemeHTTP names the one URL scheme that has no CONNECT tunnel and so
// needs Proxy-Authorization on the request itself. Named rather than
// repeated as a literal so RoundTrip's scheme check reads as intentional,
// not an arbitrary string comparison.
const schemeHTTP = "http"

// ConnTokenProvider yields a fresh connectivity-service bearer token per
// request. Accepting a request here means cancellation on the caller's
// request propagates into the token fetch — without it, a slow XSUAA
// could hang the proxied call after the client already gave up.
type ConnTokenProvider func(ctx *http.Request) (string, error)

// NewOnPremiseTransport builds a RoundTripper that routes every request
// through the Connectivity service's on-premise reverse proxy.
//
// Proxy-Authorization carries `Bearer <conn-token>`, but only on the leg
// that actually needs it. For HTTPS targets the request travels inside
// the CONNECT tunnel, so the far end (the SAP origin) never sees this
// header — only the CONNECT itself does, via
// Transport.GetProxyConnectHeader (wired here, per-request). For plain
// HTTP targets there is no tunnel, so the header has to travel with the
// forwarded request itself (the proxy consumes it before forwarding).
// Wiring the CONNECT header per-request rather than per-Transport is
// what lets the RoundTripper stop cloning the Transport on every call —
// the idle-connection pool stays shared across calls.
//
// For plain-HTTP targets the transport attaches Proxy-Authorization to
// every request it carries, including a redirect's follow-up; for HTTPS
// targets every new CONNECT tunnel carries it. Service's own client
// therefore only follows redirects that stay on the original
// scheme+host (see [ErrOnPremCrossOriginRedirect]); a caller wrapping
// this transport in its own http.Client should set an equivalent
// CheckRedirect.
func NewOnPremiseTransport(conn *ConnCredentials, provider ConnTokenProvider) (http.RoundTripper, error) {
	if conn == nil {
		return nil, ErrNoConnectivityBinding
	}
	if conn.OnPremiseProxyHost == "" || conn.OnPremiseProxyPort == "" {
		return nil, errors.New("connectivity binding has empty onpremise_proxy_host/port")
	}
	if provider == nil {
		return nil, errors.New("ConnTokenProvider is required")
	}

	proxyURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(conn.OnPremiseProxyHost, conn.OnPremiseProxyPort),
	}

	base := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		GetProxyConnectHeader: func(ctx context.Context, _ *url.URL, _ string) (http.Header, error) {
			// net/http calls this when opening a new CONNECT tunnel for
			// an HTTPS target; a request that reuses an already-open
			// tunnel does not call it again and rides on the token the
			// tunnel was opened with, since the proxy only checks
			// Proxy-Authorization at CONNECT time, not per request. We
			// expose only ctx to the provider; the existing
			// ConnTokenProvider signature takes *http.Request, so we
			// hand it a bare request carrying the right context. The
			// provider reads ctx.Done / request cancellation only.
			//
			// RoundTrip does not set Proxy-Authorization on the
			// forwarded request for an HTTPS target, since it would
			// reach the SAP origin inside the tunnel rather than
			// stopping at the proxy.
			tok, err := provider((&http.Request{}).WithContext(ctx))
			if err != nil {
				return nil, err
			}
			return http.Header{"Proxy-Authorization": []string{"Bearer " + tok}}, nil
		},
	}
	return &onPremiseRoundTripper{base: base, token: provider}, nil
}

type onPremiseRoundTripper struct {
	base  *http.Transport
	token ConnTokenProvider
}

func (t *onPremiseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone before mutating so a retry (by the caller) sees the original.
	// We do NOT clone the base Transport here: cloning would create a
	// fresh idle-connection pool on every call.
	r := req.Clone(req.Context())
	if r.URL.Scheme == schemeHTTP {
		// Plain-HTTP targets have no CONNECT tunnel, so
		// Proxy-Authorization has to travel as a request header (the
		// proxy consumes it before forwarding to the SAP origin).
		tok, err := t.token(req)
		if err != nil {
			return nil, err
		}
		r.Header.Set("Proxy-Authorization", "Bearer "+tok)
	} else {
		// HTTPS (and anything else): the request travels inside the
		// CONNECT tunnel set up via GetProxyConnectHeader, so the SAP
		// origin — not just the proxy — would see this header if we
		// set it here. Strip whatever the caller may have set and
		// leave authentication to the tunnel handshake.
		r.Header.Del("Proxy-Authorization")
	}
	return t.base.RoundTrip(r)
}

// DefaultOnPremiseTimeout is the per-call timeout for proxied requests.
// Sized for a realistic worst case: an older, heavily loaded on-prem
// SAP system reached through Cloud Connector + (for mutating routes) a
// CSRF handshake. Such calls regularly take minutes under normal load and
// have been observed up to ~5 minutes in the worst case. 10 minutes leaves
// headroom over that worst case without normalising calls that are
// genuinely hung. Override per-instance with [WithOnPremiseTimeout] when
// your SAP system is reliably faster.
//
// Keep your http.Server's WriteTimeout strictly *above* this value (e.g.
// 15 min). The asymmetry is deliberate: this per-call budget fires first
// on a hung SAP and surfaces a clean upstream_unreachable envelope;
// setting it equal to or larger than WriteTimeout would let the
// server-side timeout race this one and produce a less-helpful failure
// mode. If you raise this value, raise WriteTimeout proportionally.
const DefaultOnPremiseTimeout = 10 * time.Minute
