package btpingo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/btpingotest"
	"github.com/hochfrequenz/btpingo/internal/testkit"
)

// With WithRetry401(false) a 401 on a body-less call reaches the on-prem
// side exactly once; the default replays it (covered by the existing
// retry tests).
func Test_Service_WithRetry401False_OneRequestOn401(t *testing.T) {
	s := testkit.NewRedirectStack(t)
	var onPrem atomic.Int32
	s.OnPrem.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onPrem.Add(1)
		w.Header().Set("WWW-Authenticate", `Basic realm="SAP"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	svc, err := btpingo.NewService(s.Env, btpingo.WithRetry401(false))
	then.AssertThat(t, err, is.Nil())

	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusUnauthorized))
	then.AssertThat(t, int(onPrem.Load()), is.EqualTo(1))

	// Caches are still dropped, so the next call looks the destination up fresh.
	lookups := s.Lookups.Load()
	resp2, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	_ = resp2.Body.Close()
	then.AssertThat(t, s.Lookups.Load(), is.EqualTo(lookups+1))
}

func Test_HandlerCaller_WithRetry401False_OneRequestOn401(t *testing.T) {
	var n atomic.Int32
	c, err := btpingotest.NewHandlerCaller(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}), btpingotest.WithRetry401(false))
	then.AssertThat(t, err, is.Nil())
	defer c.Close()
	resp, err := c.CallOnPremise(context.Background(), btpingotest.DefaultDestinationName, http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	_ = resp.Body.Close()
	then.AssertThat(t, int(n.Load()), is.EqualTo(1))
}

// A 401 from the on-prem node (Basic rejected) carries a challenge.
func Test_Origin401_OnPremNode(t *testing.T) {
	s := testkit.NewRedirectStack(t)
	s.OnPrem.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="SAP NetWeaver"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	svc, err := btpingo.NewService(s.Env, btpingo.WithRetry401(false))
	then.AssertThat(t, err, is.Nil())
	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, btpingo.Origin401(resp), is.EqualTo(btpingo.Origin401OnPrem))
}

// A 401 from the connectivity proxy (bearer rejected) carries none.
func Test_Origin401_Proxy(t *testing.T) {
	s := testkit.NewRedirectStack(t)
	var onPrem atomic.Int32
	s.OnPrem.Config.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { onPrem.Add(1) })
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
	}))
	t.Cleanup(proxy.Close)
	u, _ := url.Parse(proxy.URL)
	s.Env.Conn.OnPremiseProxyHost, s.Env.Conn.OnPremiseProxyPort = u.Hostname(), u.Port()
	svc, err := btpingo.NewService(s.Env, btpingo.WithRetry401(false))
	then.AssertThat(t, err, is.Nil())
	resp, err := svc.CallOnPremise(context.Background(), "D", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, btpingo.Origin401(resp), is.EqualTo(btpingo.Origin401Proxy))
	then.AssertThat(t, int(onPrem.Load()), is.EqualTo(0))
}

func Test_Origin401_NotA401(t *testing.T) {
	then.AssertThat(t, btpingo.Origin401(nil), is.EqualTo(btpingo.Origin401None))
	then.AssertThat(t, btpingo.Origin401(&http.Response{StatusCode: 403, Header: http.Header{"Www-Authenticate": {"Basic"}}}), is.EqualTo(btpingo.Origin401None))
}

// Default: the body-less 401 is replayed once (two requests), mirroring Service.
func Test_HandlerCaller_DefaultRetry401_TwoRequestsOn401(t *testing.T) {
	var n atomic.Int32
	c, err := btpingotest.NewHandlerCaller(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	then.AssertThat(t, err, is.Nil())
	defer c.Close()
	resp, err := c.CallOnPremise(context.Background(), btpingotest.DefaultDestinationName, http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	_ = resp.Body.Close()
	then.AssertThat(t, int(n.Load()), is.EqualTo(2))
}
