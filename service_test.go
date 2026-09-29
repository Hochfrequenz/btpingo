package btpingo_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/internal/testkit"
)

// testOldPassword / testNewPassword stand in for a BasicAuthentication
// password before/after a cockpit rotation, in the 401-retry tests
// below that simulate the destination cache serving a stale one.
const (
	testOldPassword = "old"
	testNewPassword = "new"
)

func Test_Service_CallOnPremise_EndToEnd(t *testing.T) {
	s := testkit.NewBTPStack(t, `{
		"destinationConfiguration":{
			"Name":"MySap","Type":"HTTP","URL":"`+"http://sap.internal:8000"+`",
			"Authentication":"BasicAuthentication","ProxyType":"OnPremise",
			"User":"u","Password":"p",
			"CloudConnectorLocationId":"loc-42"
		}
	}`)
	// Point the destination URL at our fake on-prem so the request actually
	// goes somewhere the proxy can reach. We rebuild the stack JSON with a
	// working URL; the Destination's proxy routing goes via our fake proxy.
	s = testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{
			"Name":"MySap","Type":"HTTP","URL":%q,
			"Authentication":"BasicAuthentication","ProxyType":"OnPremise",
			"User":"u","Password":"p",
			"CloudConnectorLocationId":"loc-42"
		}
	}`, s.OnPrem.URL))

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	// Feed the inbound request with headers the service should filter.
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer forwarded-user-jwt")
	hdr.Set("Cookie", "approuter-sess=secret")
	hdr.Set("X-Trace-ID", "abc")

	resp, err := svc.CallOnPremise(context.Background(), "MySap", http.MethodGet, "/sap/opu/odata/ping", hdr, nil)
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusOK))
	_ = resp.Body.Close()

	// Basic-auth replaced the forwarded user JWT.
	then.AssertThat(t, strings.HasPrefix(resp.Header.Get("X-Received-Auth"), "Basic "), is.True())
	// Cookie was filtered out.
	then.AssertThat(t, resp.Header.Get("X-Received-Cookie"), is.EqualTo(""))
	// Neutral UA set when caller didn't supply one.
	then.AssertThat(t, strings.Contains(resp.Header.Get("X-Received-UA"), "btpingo"), is.True())
	// Location ID forwarded from the destination.
	then.AssertThat(t, resp.Header.Get("X-Received-Location"), is.EqualTo("loc-42"))
	// Exactly two XSUAA exchanges: one for dest-service, one for connectivity.
	then.AssertThat(t, int(s.Tokens.Load()), is.EqualTo(2))
}

func Test_Service_CallOnPremise_NoLocationIDHeaderWhenAbsent(t *testing.T) {
	s := testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{
			"Name":"D","Type":"HTTP","URL":%q,
			"Authentication":"NoAuthentication","ProxyType":"OnPremise"
		}
	}`, "placeholder"))
	s = testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{
			"Name":"D","Type":"HTTP","URL":%q,
			"Authentication":"NoAuthentication","ProxyType":"OnPremise"
		}
	}`, s.OnPrem.URL))

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, resp.Header.Get("X-Received-Location"), is.EqualTo(""))
}

func Test_Service_CallOnPremise_DestinationNotFound(t *testing.T) {
	s := testkit.NewBTPStack(t, `ignored`)
	s.Dest.Close()
	s.Dest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(s.Dest.Close)
	s.Env.Dest.URI = s.Dest.URL

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	_, err = svc.CallOnPremise(context.Background(), "Missing", http.MethodGet, "/", nil, nil)
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, errors.Is(err, btpingo.ErrDestinationNotFound), is.True())
}

func Test_NewService_RequiresBindings(t *testing.T) {
	_, err := btpingo.NewService(nil)
	then.AssertThat(t, err, is.Not(is.Nil()))

	_, err = btpingo.NewService(&btpingo.Env{XSUAA: &btpingo.XSUAACredentials{URL: "https://u", XSAppName: "a"}})
	then.AssertThat(t, errors.Is(err, btpingo.ErrNoDestinationBinding), is.True())

	_, err = btpingo.NewService(&btpingo.Env{
		XSUAA: &btpingo.XSUAACredentials{URL: "https://u", XSAppName: "a"},
		Dest:  &btpingo.DestCredentials{URI: "https://d", ClientID: "c", ClientSecret: "s", URL: "https://u"},
	})
	then.AssertThat(t, errors.Is(err, btpingo.ErrNoConnectivityBinding), is.True())
}

func Test_Service_AuthenticatorsExposesRegistry(t *testing.T) {
	s := testkit.NewBTPStack(t, `{"destinationConfiguration":{"URL":"x"}}`)
	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, svc.Authenticators() != nil, is.True())
}

func Test_Service_CallOnPremise_RetriesOn401(t *testing.T) {
	// The stack helper hard-codes its proxy to forward to its own onPrem,
	// so for this test we install a single onPrem (401-then-200) and then
	// build the stack with that URL as the destination target — the
	// proxy's forward URL is what matters since the stack overrides path.
	var calls atomic.Int32
	flipServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer flipServer.Close()

	s := testkit.NewBTPStack(t, "placeholder")
	// Swap the stack's onPrem for our flip-server by reusing its address.
	// Simpler: reach into the helper — close its default onPrem and make
	// the proxy forward to flipServer instead. We can accomplish the same
	// by discarding the stack's auto-URL and rebuilding destBody to point
	// at flipServer, since the proxy handler uses s.OnPrem.URL directly
	// (hard-coded in the helper). Override it by replacing the proxy.
	s.Proxy.Close()
	s.Proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Proxy-Authorization"), "Bearer ") {
			http.Error(w, "missing proxy auth", http.StatusProxyAuthRequired)
			return
		}
		u, err := url.Parse(r.RequestURI)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		outReq, _ := http.NewRequestWithContext(r.Context(), r.Method, flipServer.URL+u.Path, r.Body)
		for k, vs := range r.Header {
			if strings.EqualFold(k, "Proxy-Authorization") {
				continue
			}
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultClient.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(s.Proxy.Close)
	pu, _ := url.Parse(s.Proxy.URL)
	s.Env.Conn.OnPremiseProxyHost = pu.Hostname()
	s.Env.Conn.OnPremiseProxyPort = pu.Port()

	// Destination URL can be anything HTTP; the proxy overrides it.
	s.Dest.Close()
	s.Dest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,"Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`, flipServer.URL)
	}))
	t.Cleanup(s.Dest.Close)
	s.Env.Dest.URI = s.Dest.URL

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusOK))
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))
}

func Test_Service_CallOnPremise_PropagatesAuthenticatorError(t *testing.T) {
	s := testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,
			"Authentication":"BasicAuthentication","ProxyType":"OnPremise","User":""}
	}`, "http://placeholder"))
	s = testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,
			"Authentication":"BasicAuthentication","ProxyType":"OnPremise","User":""}
	}`, s.OnPrem.URL))

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	// BasicAuthentication with empty User fails inside the authenticator
	// registry — the error must surface from CallOnPremise, not be silently
	// swallowed.
	_, err = svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/", nil, nil)
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, strings.Contains(err.Error(), "apply destination auth"), is.True())
}

func Test_Service_CallOnPremise_RejectsPathTraversal(t *testing.T) {
	s := testkit.NewBTPStack(t, `{"destinationConfiguration":{"URL":"http://x"}}`)
	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	_, err = svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/foo/../../admin", nil, nil)
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, strings.Contains(err.Error(), "traversal"), is.True())
}

// Test_Service_CallOnPremise_RejectsPercentEncodedPath guards the second
// half of the traversal defence. A literal `..` is easy to spot; what the
// check must also stop are percent-encoded variants (`%2e%2e`, mixed case,
// `%2e.`), because some SAP HTTP frontends decode before applying
// path-resolution rules. Rather than chase decoder quirks we reject any
// `%` in pathSuffix — these cases cover the common bypass shapes plus a
// benign-looking space encoding that should also trip the guard.
func Test_Service_CallOnPremise_RejectsPercentEncodedPath(t *testing.T) {
	s := testkit.NewBTPStack(t, `{"destinationConfiguration":{"URL":"http://x"}}`)
	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	cases := []string{
		"/foo/%2e%2e/bar",
		"/foo/%2E%2E/bar",
		"/foo/%2e./bar",
		"/foo/%2e%2e%2fbar",
		"/foo%20bar",
	}
	for _, suffix := range cases {
		_, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, suffix, nil, nil)
		then.AssertThat(t, err, is.Not(is.Nil()))
		then.AssertThat(t, strings.Contains(err.Error(), "percent-encoded"), is.True())
	}
}

// Test_Service_CallOnPremise_RejectsUnparseableDestinationURL covers the
// SSRF host-pinning guard's parse step: a destination whose URL the SAP
// Destination service hands back cannot be turned into a request target,
// so the call fails closed rather than dialling an attacker-influenced
// host. url.Parse rejects an unterminated IPv6 literal, which is the
// cheapest way to drive that branch through the public API.
func Test_Service_CallOnPremise_RejectsUnparseableDestinationURL(t *testing.T) {
	s := testkit.NewBTPStack(t, `{"destinationConfiguration":{"URL":"http://[::1"}}`)
	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	_, err = svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/ping", nil, nil)
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, strings.Contains(err.Error(), "parse destination url"), is.True())
}

// Test_Service_CallOnPremise_RejectsCrossOriginRedirect: a redirect to
// another scheme, host or port is not followed. The request pin in
// callOnce only sees the first request; without a CheckRedirect policy
// net/http follows the Location through the same Connectivity transport.
func Test_Service_CallOnPremise_RejectsCrossOriginRedirect(t *testing.T) {
	for _, path := range []string{"/redirect-off-host", "/redirect-other-scheme", "/redirect-other-port"} {
		t.Run(strings.TrimPrefix(path, "/"), func(t *testing.T) {
			s := testkit.NewRedirectStack(t)
			svc, err := btpingo.NewService(s.Env)
			then.AssertThat(t, err, is.Nil())

			resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, path, nil, nil)
			then.AssertThat(t, resp == nil, is.True())
			then.AssertThat(t, int(s.StrayCalls.Load()), is.EqualTo(0))
			then.AssertThat(t, errors.Is(err, btpingo.ErrOnPremCrossOriginRedirect), is.True())
			kind, _ := btpingo.ClassifyOnPremError(err)
			then.AssertThat(t, kind, is.EqualTo(btpingo.OnPremFailureTransport))
		})
	}
}

// Test_Service_CallOnPremise_FollowsSameOriginRedirect: a redirect that
// stays on the destination's origin is still followed, including one
// that spells the host in another case.
func Test_Service_CallOnPremise_FollowsSameOriginRedirect(t *testing.T) {
	for _, path := range []string{"/redirect-same-host", "/redirect-host-case"} {
		t.Run(strings.TrimPrefix(path, "/"), func(t *testing.T) {
			s := testkit.NewRedirectStack(t)
			svc, err := btpingo.NewService(s.Env)
			then.AssertThat(t, err, is.Nil())

			resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, path, nil, nil)
			if err != nil {
				t.Fatalf("CallOnPremise(%s): %v", path, err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			then.AssertThat(t, err, is.Nil())
			then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusOK))
			then.AssertThat(t, string(body), is.EqualTo(`{"ok":true,"path":"/landed"}`))
			then.AssertThat(t, int(s.StrayCalls.Load()), is.EqualTo(0))
		})
	}
}

// Test_Service_CallOnPremise_CrossOriginOnLastHopReportsSentinel: when the
// redirect that reaches the hop limit is also cross-origin, the caller
// still gets ErrOnPremCrossOriginRedirect, not the generic limit error.
func Test_Service_CallOnPremise_CrossOriginOnLastHopReportsSentinel(t *testing.T) {
	s := testkit.NewRedirectStack(t)
	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/redirect-chain-1", nil, nil)
	then.AssertThat(t, resp == nil, is.True())
	then.AssertThat(t, int(s.StrayCalls.Load()), is.EqualTo(0))
	then.AssertThat(t, errors.Is(err, btpingo.ErrOnPremCrossOriginRedirect), is.True())
}

// rewritingAuthenticator is a custom DestinationAuthenticator that steers
// the request to another host, for the post-Apply pin check.
type rewritingAuthenticator struct{}

func (rewritingAuthenticator) AuthType() btpingo.AuthType { return btpingo.AuthNone }
func (rewritingAuthenticator) Apply(_ context.Context, req *http.Request, _ *btpingo.Destination) error {
	req.URL.Host = "elsewhere.example"
	return nil
}

// Test_Service_CallOnPremise_RejectsAuthenticatorRewritingHost: an
// authenticator receives the mutable request, so the scheme+host pin is
// re-checked after it runs.
func Test_Service_CallOnPremise_RejectsAuthenticatorRewritingHost(t *testing.T) {
	s := testkit.NewRedirectStack(t)
	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())
	svc.Authenticators().Register(rewritingAuthenticator{})

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, resp == nil, is.True())
	then.AssertThat(t, int(s.StrayCalls.Load()), is.EqualTo(0))
	then.AssertThat(t, int(s.Calls.Load()), is.EqualTo(0))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	then.AssertThat(t, strings.Contains(err.Error(), "destination authenticator changed"), is.True())
}

// Test_Service_CallOnPremise_StopsRedirectLoop: a custom CheckRedirect
// replaces net/http's 10-hop limit, so the policy must re-implement it.
// Without it a same-origin loop runs until the on-prem timeout.
func Test_Service_CallOnPremise_StopsRedirectLoop(t *testing.T) {
	s := testkit.NewRedirectStack(t)
	svc, err := btpingo.NewService(s.Env, btpingo.WithOnPremiseTimeout(5*time.Second))
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/redirect-loop", nil, nil)
	then.AssertThat(t, resp == nil, is.True())
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, errors.Is(err, btpingo.ErrOnPremCrossOriginRedirect), is.False())
	then.AssertThat(t, errors.Is(err, context.DeadlineExceeded), is.False())
	then.AssertThat(t, int(s.Calls.Load()), is.EqualTo(10))
}

// Test_Service_CallOnPremise_RejectsHostMismatch covers the SSRF
// host-pinning guard itself. A destination URL with no host ("http://")
// trims to "http:", so a suffix of "//evil.example/x" — no "..", no "%",
// nothing CallOnPremise's own checks reject — would otherwise build the
// target http://evil.example/x and dial that host (via the proxy, which
// the test's s.Calls counter observes).
func Test_Service_CallOnPremise_RejectsHostMismatch(t *testing.T) {
	s := testkit.NewBTPStack(t, `{"destinationConfiguration":{"URL":"http://"}}`)
	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "//evil.example/x", nil, nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	then.AssertThat(t, int(s.Calls.Load()), is.EqualTo(0))
	if err == nil {
		t.Fatal("expected host-mismatch error, got nil")
	}
	then.AssertThat(t, strings.Contains(err.Error(), "does not match destination host"), is.True())
}

// Test_NewService_ZeroOptionsFallBackToDefaults pins the explicit
// "zero means default" semantics on ServiceOptions. Callers that
// compose a struct-style options without knowing which fields to set
// should still end up with the built-in timeouts and UA. Covers the
// three fallback branches that a direct-call test cannot reach when
// explicit WithX(...) values are passed.
func Test_NewService_ZeroOptionsFallBackToDefaults(t *testing.T) {
	s := testkit.NewBTPStack(t, `{"destinationConfiguration":{"URL":"http://x"}}`)

	svc, err := btpingo.NewService(s.Env,
		btpingo.WithUserAgent(""),
		btpingo.WithMgmtTimeout(0),
		btpingo.WithOnPremiseTimeout(0),
	)
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, svc != nil, is.True())
}

// Test_Service_CallOnPremise_WithUserAgentOverride pins the option
// knob: DefaultUserAgent is only a fallback; services should set their
// own via btpingo.WithUserAgent so SAP-side traces can tell callers
// apart.
func Test_Service_CallOnPremise_WithUserAgentOverride(t *testing.T) {
	first := testkit.NewBTPStack(t, "placeholder")
	s := testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,"Authentication":"NoAuthentication","ProxyType":"OnPremise"}
	}`, first.OnPrem.URL))

	svc, err := btpingo.NewService(s.Env, btpingo.WithUserAgent("my-service/v1.2.3"))
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, resp.Header.Get("X-Received-UA"), is.EqualTo("my-service/v1.2.3"))
}

// Test_Service_CallOnPremise_CapsOversizedResponse pins the contract
// that a misbehaving SAP / misrouted CC topology which
// streams more than the configured cap must surface
// ErrOnPremResponseTooLarge from the caller's io.ReadAll, NOT silently
// fill memory. Pins the memory invariant via a length check on the
// buffered bytes.
func Test_Service_CallOnPremise_CapsOversizedResponse(t *testing.T) {
	// The "SAP" side streams 4 KiB; the cap below is 1 KiB.
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("X"), 4096))
	}))
	defer big.Close()

	s := testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,"Authentication":"NoAuthentication","ProxyType":"OnPremise"}
	}`, big.URL))
	// Repoint the stack's proxy at `big` rather than the default
	// s.OnPrem (which always returns a small JSON). Same swap pattern
	// the WithOnPremiseTimeout test uses.
	s.Proxy.Close()
	s.Proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Proxy-Authorization"), "Bearer ") {
			http.Error(w, "missing proxy auth", http.StatusProxyAuthRequired)
			return
		}
		u, _ := url.Parse(r.RequestURI)
		outReq, _ := http.NewRequestWithContext(r.Context(), r.Method, big.URL+u.Path, r.Body)
		resp, err := http.DefaultClient.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(s.Proxy.Close)
	pu, _ := url.Parse(s.Proxy.URL)
	s.Env.Conn.OnPremiseProxyHost = pu.Hostname()
	s.Env.Conn.OnPremiseProxyPort = pu.Port()

	svc, err := btpingo.NewService(s.Env, btpingo.WithOnPremResponseSizeLimit(1024))
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, errors.Is(err, btpingo.ErrOnPremResponseTooLarge), is.True())
	// Memory invariant: never buffer more than the cap (plus the +1
	// byte the wrapper reads to detect overflow).
	then.AssertThat(t, int64(len(body)) <= 1025, is.True())
}

// Test_Service_CallOnPremise_AllowsResponseUnderLimit pins the happy
// path: a response well under the cap reads through unchanged. Pairs
// with the cap test to prove the wrapper is transparent on legitimate
// traffic.
func Test_Service_CallOnPremise_AllowsResponseUnderLimit(t *testing.T) {
	s := testkit.NewBTPStack(t, `{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://placeholder","Authentication":"NoAuthentication","ProxyType":"OnPremise"}
	}`)
	// newBTPStack's on-prem returns a small JSON ({"ok":true,...}),
	// well under any sensible cap.

	svc, err := btpingo.NewService(s.Env, btpingo.WithOnPremResponseSizeLimit(1024))
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, len(body) > 0, is.True())
}

// Test_Service_CallOnPremise_NegativeSizeLimitFallsBackToDefault pins
// the fallback: a negative WithOnPremResponseSizeLimit is not a
// sensible cap (limitedOnPremBody's slice math assumes non-negative),
// so NewService must treat it like zero and fall back to
// DefaultOnPremResponseSizeLimit rather than let it reach the wrapper
// and panic on the first read.
func Test_Service_CallOnPremise_NegativeSizeLimitFallsBackToDefault(t *testing.T) {
	s := testkit.NewBTPStack(t, `{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://placeholder","Authentication":"NoAuthentication","ProxyType":"OnPremise"}
	}`)
	// newBTPStack's on-prem returns a small JSON ({"ok":true,...}),
	// well under any sensible cap.

	svc, err := btpingo.NewService(s.Env, btpingo.WithOnPremResponseSizeLimit(-1))
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, len(body) > 0, is.True())
}

// Test_Service_CallOnPremise_WithOnPremiseTimeout proves the timeout
// option actually reaches the http.Client wrapping the on-prem transport.
// We stand up an on-prem server that sleeps longer than the configured
// budget; the call must fail with a timeout-shaped error.
func Test_Service_CallOnPremise_WithOnPremiseTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	s := testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,"Authentication":"NoAuthentication","ProxyType":"OnPremise"}
	}`, slow.URL))
	// Redirect the stack's proxy to the slow server too, so the whole
	// call chain routes through it.
	s.Proxy.Close()
	s.Proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Proxy-Authorization"), "Bearer ") {
			http.Error(w, "missing proxy auth", http.StatusProxyAuthRequired)
			return
		}
		u, err := url.Parse(r.RequestURI)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		outReq, _ := http.NewRequestWithContext(r.Context(), r.Method, slow.URL+u.Path, r.Body)
		resp, err := http.DefaultClient.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
	}))
	t.Cleanup(s.Proxy.Close)
	pu, _ := url.Parse(s.Proxy.URL)
	s.Env.Conn.OnPremiseProxyHost = pu.Hostname()
	s.Env.Conn.OnPremiseProxyPort = pu.Port()

	svc, err := btpingo.NewService(s.Env, btpingo.WithOnPremiseTimeout(50*time.Millisecond))
	then.AssertThat(t, err, is.Nil())

	_, err = svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Not(is.Nil()))
	// The timeout bubbles up as a net/http client-side deadline error —
	// we just assert that it looks timeout-shaped, not the exact text.
	then.AssertThat(t,
		strings.Contains(err.Error(), "deadline") ||
			strings.Contains(err.Error(), "Client.Timeout") ||
			strings.Contains(err.Error(), "timeout"),
		is.True())
}

// Test_Service_CallOnPremise_RetriesOn401WithRefreshedDestination covers
// the fix for #4: a 401 must not only invalidate the connectivity
// token, it must also drop the cached *destination* and look it up
// again, because the 401 can just as well be caused by a destination
// credential (e.g. a BasicAuthentication password) that was rotated in
// the cockpit. Without the fix, the retry would replay the stale
// "old" password from the cached destination and fail again.
//
// The fake Destination service hands back password "old" on its first
// lookup and "new" on every lookup after that. The fake on-prem server
// answers 401 unless the Basic-auth password is "new". The call must
// succeed on the retry, with exactly two destination lookups and two
// on-prem calls — one attempt with the stale destination, one with the
// refreshed one.
func Test_Service_CallOnPremise_RetriesOn401WithRefreshedDestination(t *testing.T) {
	s := testkit.NewBTPStack(t, "placeholder")

	var onPremCalls atomic.Int32
	s.OnPrem.Close()
	s.OnPrem = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onPremCalls.Add(1)
		_, pass, _ := r.BasicAuth()
		if pass != testNewPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(s.OnPrem.Close)

	var destLookups atomic.Int32
	s.Dest.Close()
	s.Dest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := destLookups.Add(1)
		password := testNewPassword
		if n == 1 {
			password = testOldPassword
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,
			"Authentication":"BasicAuthentication","ProxyType":"OnPremise","User":"u","Password":%q}}`,
			testkit.RedirectDest, password)
	}))
	t.Cleanup(s.Dest.Close)
	s.Env.Dest.URI = s.Dest.URL

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusOK))
	then.AssertThat(t, int(destLookups.Load()), is.EqualTo(2))
	then.AssertThat(t, int(onPremCalls.Load()), is.EqualTo(2))
}

// Test_Service_CallOnPremise_401OnRetryIsReturned makes sure the fix
// does not turn the single retry into a loop: if the on-prem server
// still answers 401 after the destination was refreshed (e.g. the
// rotation didn't fix the actual problem), CallOnPremise returns that
// 401 response to the caller instead of retrying again. Exactly one
// retry happens — two destination lookups, two on-prem calls.
func Test_Service_CallOnPremise_401OnRetryIsReturned(t *testing.T) {
	s := testkit.NewBTPStack(t, "placeholder")

	var onPremCalls atomic.Int32
	s.OnPrem.Close()
	s.OnPrem = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onPremCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(s.OnPrem.Close)

	var destLookups atomic.Int32
	s.Dest.Close()
	s.Dest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destLookups.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,
			"Authentication":"BasicAuthentication","ProxyType":"OnPremise","User":"u","Password":"whatever"}}`,
			testkit.RedirectDest)
	}))
	t.Cleanup(s.Dest.Close)
	s.Env.Dest.URI = s.Dest.URL

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusUnauthorized))
	then.AssertThat(t, int(destLookups.Load()), is.EqualTo(2))
	then.AssertThat(t, int(onPremCalls.Load()), is.EqualTo(2))
}

// Test_Service_CallOnPremise_BodyCarrying401DropsDestinationForNextCall
// covers the other half of the #4 fix: a body-carrying call cannot be
// retried within itself — its io.Reader is already consumed by the
// failed attempt — so it must return the 401 to the caller as-is.
// But the token and destination invalidation must still run for that
// call, not only for retryable body-less ones, so the cache dropped
// here is looked up fresh by the very next call on the same
// destination instead of serving the stale, rotated-away credential
// for the rest of the cache TTL.
//
// The fake Destination service hands back password "old" on its first
// lookup and "new" on every lookup after. The fake on-prem server 401s
// unless the Basic-auth password is "new". Call 1 is body-carrying and
// gets the 401 back unretried: exactly one on-prem call, one
// destination lookup. Call 2 is body-less and succeeds on its first
// on-prem attempt because it looked the destination up again: exactly
// two destination lookups and two on-prem calls across both calls.
//
// If the Invalidate calls were still nested inside the `body == nil`
// branch (the pre-fix code CallOnPremise had), call 1 would never
// invalidate anything, call 2 would replay the cached "old" password
// from the destination cache, and this test would fail with a second
// 401 instead of the expected 200.
func Test_Service_CallOnPremise_BodyCarrying401DropsDestinationForNextCall(t *testing.T) {
	s := testkit.NewBTPStack(t, "placeholder")

	var onPremCalls atomic.Int32
	s.OnPrem.Close()
	s.OnPrem = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onPremCalls.Add(1)
		_, pass, _ := r.BasicAuth()
		if pass != testNewPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(s.OnPrem.Close)

	var destLookups atomic.Int32
	s.Dest.Close()
	s.Dest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := destLookups.Add(1)
		password := testNewPassword
		if n == 1 {
			password = testOldPassword
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,
			"Authentication":"BasicAuthentication","ProxyType":"OnPremise","User":"u","Password":%q}}`,
			testkit.RedirectDest, password)
	}))
	t.Cleanup(s.Dest.Close)
	s.Env.Dest.URI = s.Dest.URL

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	// Call 1: body-carrying, gets 401, cannot be retried in-call.
	resp1, err := svc.CallOnPremise(context.Background(), "D", http.MethodPost, "/x", nil, bytes.NewReader([]byte("payload")))
	then.AssertThat(t, err, is.Nil())
	_ = resp1.Body.Close()
	then.AssertThat(t, resp1.StatusCode, is.EqualTo(http.StatusUnauthorized))
	then.AssertThat(t, int(onPremCalls.Load()), is.EqualTo(1))
	then.AssertThat(t, int(destLookups.Load()), is.EqualTo(1))

	// Call 2: body-less, on a fresh destination lookup because call 1
	// dropped the cache — succeeds on the first on-prem attempt.
	resp2, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp2.Body.Close() }()
	then.AssertThat(t, resp2.StatusCode, is.EqualTo(http.StatusOK))
	then.AssertThat(t, int(destLookups.Load()), is.EqualTo(2))
	then.AssertThat(t, int(onPremCalls.Load()), is.EqualTo(2))
}

// Test_Service_CallOnPremise_401RetryLookupNotFound covers the retry's
// own error path: if the destination was deleted between the first
// 401 and the retry (e.g. an operator removed it while chasing the
// original outage), the second Lookup call returns
// ErrDestinationNotFound and CallOnPremise surfaces that error rather
// than swallowing it — so a caller feeding it to ClassifyOnPremError
// gets OnPremFailureDestinationNotFound, not a generic transport
// failure.
func Test_Service_CallOnPremise_401RetryLookupNotFound(t *testing.T) {
	s := testkit.NewBTPStack(t, "placeholder")

	s.OnPrem.Close()
	s.OnPrem = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(s.OnPrem.Close)

	var destLookups atomic.Int32
	s.Dest.Close()
	s.Dest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := destLookups.Add(1)
		if n >= 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,
			"Authentication":"BasicAuthentication","ProxyType":"OnPremise","User":"u","Password":%q}}`,
			testkit.RedirectDest, testOldPassword)
	}))
	t.Cleanup(s.Dest.Close)
	s.Env.Dest.URI = s.Dest.URL

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	_, err = svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, errors.Is(err, btpingo.ErrDestinationNotFound), is.True())

	kind, _ := btpingo.ClassifyOnPremError(err)
	then.AssertThat(t, kind, is.EqualTo(btpingo.OnPremFailureDestinationNotFound))
}
