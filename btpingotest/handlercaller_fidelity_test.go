package btpingotest_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/btpingotest"
	"github.com/hochfrequenz/btpingo/internal/testkit"
)

// fidelityHandler serves the behaviours both a real Service and a
// HandlerCaller are compared on. It uses only relative redirects and
// cross-origin absolute ones, so it works behind both.
func fidelityHandler(calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ok":
			w.Header().Set("X-Test", "yes")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("hello"))
		case r.URL.Path == "/notfound":
			http.Error(w, "nope", http.StatusNotFound)
		case r.URL.Path == "/empty":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/head" && r.Method == http.MethodHead:
			w.Header().Set("Content-Length", "1234")
		case r.URL.Path == "/redirect-same":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case r.URL.Path == "/redirect-off":
			http.Redirect(w, r, "http://elsewhere.example/landed", http.StatusFound)
		case r.URL.Path == "/gzip":
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write([]byte("zipped body"))
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(buf.Bytes())
		case r.URL.Path == "/big":
			_, _ = w.Write(bytes.Repeat([]byte("x"), 100))
		case r.URL.Path == "/unauth":
			calls.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	})
}

type outcome struct {
	status        int
	contentLength int64
	xTest         string
	contentType   string
	encoding      string
	hasDate       bool
	body          string
	readErr       bool
	callErr       bool
	crossOrigin   bool
	tooLarge      bool
	kind          btpingo.OnPremFailureKind
}

func observe(resp *http.Response, err error) outcome {
	var o outcome
	if err != nil {
		o.callErr = true
		o.crossOrigin = errors.Is(err, btpingo.ErrOnPremCrossOriginRedirect)
		o.kind, _ = btpingo.ClassifyOnPremError(err)
		return o
	}
	defer func() { _ = resp.Body.Close() }()
	o.status = resp.StatusCode
	o.contentLength = resp.ContentLength
	o.xTest = resp.Header.Get("X-Test")
	o.contentType = resp.Header.Get("Content-Type")
	o.encoding = resp.Header.Get("Content-Encoding")
	o.hasDate = resp.Header.Get("Date") != ""
	b, rerr := io.ReadAll(resp.Body)
	o.body = string(b)
	if rerr != nil {
		o.readErr = true
		o.tooLarge = errors.Is(rerr, btpingo.ErrOnPremResponseTooLarge)
		o.kind, _ = btpingo.ClassifyOnPremError(rerr)
	}
	return o
}

// Test_HandlerCaller_MatchesService_Differential runs one handler behind a
// real btpingo.Service (fake destination service, connectivity proxy) and
// behind a HandlerCaller and compares everything a caller can observe.
func Test_HandlerCaller_MatchesService_Differential(t *testing.T) {
	cases := []struct {
		name, method, path string
		body               io.Reader
		wantCalls          int32 // handler hits on /unauth, 0 = not checked
	}{
		{name: "200 with headers", method: http.MethodGet, path: "/ok"},
		{name: "404", method: http.MethodGet, path: "/notfound"},
		{name: "204 empty", method: http.MethodGet, path: "/empty"},
		{name: "HEAD keeps Content-Length", method: http.MethodHead, path: "/head"},
		{name: "same-origin redirect followed", method: http.MethodGet, path: "/redirect-same"},
		{name: "cross-origin redirect refused", method: http.MethodGet, path: "/redirect-off"},
		{name: "gzip decoded transparently", method: http.MethodGet, path: "/gzip"},
		{name: "oversized body", method: http.MethodGet, path: "/big"},
		{name: "401 without body is retried once", method: http.MethodGet, path: "/unauth", wantCalls: 2},
		{name: "401 with body is not retried", method: http.MethodPost, path: "/unauth", body: strings.NewReader("x"), wantCalls: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var svcCalls, hcCalls atomic.Int32

			stack := testkit.NewRedirectStack(t)
			stack.OnPrem.Config.Handler = fidelityHandler(&svcCalls)
			svc, err := btpingo.NewService(stack.Env, btpingo.WithOnPremResponseSizeLimit(50))
			then.AssertThat(t, err, is.Nil())
			hc := newCaller(t, fidelityHandler(&hcCalls), btpingotest.WithDestinationName("D"), btpingotest.WithResponseSizeLimit(50))

			var b1, b2 io.Reader
			if c.body != nil {
				b1, b2 = strings.NewReader("x"), strings.NewReader("x")
			}
			want := observe(svc.CallOnPremise(context.Background(), "D", c.method, c.path, nil, b1))
			got := observe(hc.CallOnPremise(context.Background(), "D", c.method, c.path, nil, b2))
			then.AssertThat(t, got, is.EqualTo(want))
			then.AssertThat(t, hcCalls.Load(), is.EqualTo(svcCalls.Load()))
			if c.wantCalls != 0 {
				then.AssertThat(t, hcCalls.Load(), is.EqualTo(c.wantCalls))
			}
		})
	}
}

func Test_HandlerCaller_FollowsRedirectsWithLimit(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		if err != nil || n >= 100 {
			http.Error(w, "end", http.StatusOK)
			return
		}
		http.Redirect(w, r, "/hop/"+strconv.Itoa(n+1), http.StatusFound)
	})
	cl := newCaller(t, h)
	_, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/hop/0", nil, nil)
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, strings.Contains(err.Error(), "stopped after 10 redirects"), is.True())
	then.AssertThat(t, errors.Is(err, btpingo.ErrOnPremCrossOriginRedirect), is.False())
	resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/hop/95", nil, nil)
	then.AssertThat(t, err, is.Nil())
	_ = resp.Body.Close()
}

func Test_HandlerCaller_RealHTTPSemantics(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("12345"))
	})
	cl := newCaller(t, h)
	resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	then.AssertThat(t, resp.ContentLength, is.EqualTo(int64(5)))
	then.AssertThat(t, resp.Header.Get("Date") != "", is.True())
	then.AssertThat(t, resp.Header.Get("Content-Type"), is.EqualTo("text/plain; charset=utf-8"))
}

// csrfSAP is a fake ICF node with the CSRF handshake: fetch with
// X-CSRF-Token: Fetch, POST needs token and session cookie.
type csrfSAP struct {
	fetches, posts atomic.Int32
	token          atomic.Value // string
	forbidden      atomic.Bool  // answer POST with a plain 403
}

func (s *csrfSAP) rotate(tok string) { s.token.Store(tok) }

func (s *csrfSAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cur, _ := s.token.Load().(string)
	if r.Method == http.MethodGet && r.URL.Path == btpingo.DefaultCSRFFetchPath {
		s.fetches.Add(1)
		w.Header().Set("X-CSRF-Token", cur)
		http.SetCookie(w, &http.Cookie{Name: "SAP_SESSIONID_X_100", Value: "sess-" + cur})
		w.WriteHeader(http.StatusOK)
		return
	}
	s.posts.Add(1)
	if s.forbidden.Load() {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Header.Get("X-CSRF-Token") != cur || r.Header.Get("Cookie") != "SAP_SESSIONID_X_100=sess-"+cur {
		w.Header().Set("X-CSRF-Token", "Required")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	b, _ := io.ReadAll(r.Body)
	_, _ = w.Write(b)
}

func Test_HandlerCaller_Mutating_CSRFHandshake(t *testing.T) {
	post := func(cl *btpingotest.HandlerCaller, body string) (*http.Response, error) {
		return cl.CallOnPremiseMutating(context.Background(), "SAP", http.MethodPost, "/sap/x", nil, strings.NewReader(body))
	}
	t.Run("fetch once, then cached", func(t *testing.T) {
		sap := &csrfSAP{}
		sap.rotate("t1")
		cl := newCaller(t, sap)
		for range 2 {
			resp, err := post(cl, "payload")
			then.AssertThat(t, err, is.Nil())
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusOK))
			then.AssertThat(t, string(b), is.EqualTo("payload"))
		}
		then.AssertThat(t, sap.fetches.Load(), is.EqualTo(int32(1)))
	})
	t.Run("recycled session: refetch and retry once, body replayed", func(t *testing.T) {
		sap := &csrfSAP{}
		sap.rotate("t1")
		cl := newCaller(t, sap)
		resp, err := post(cl, "a")
		then.AssertThat(t, err, is.Nil())
		_ = resp.Body.Close()
		sap.rotate("t2")
		resp, err = post(cl, "again")
		then.AssertThat(t, err, is.Nil())
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusOK))
		then.AssertThat(t, string(b), is.EqualTo("again"))
		then.AssertThat(t, sap.fetches.Load(), is.EqualTo(int32(2)))
	})
	t.Run("plain 403 is not retried", func(t *testing.T) {
		sap := &csrfSAP{}
		sap.rotate("t1")
		sap.forbidden.Store(true)
		cl := newCaller(t, sap)
		resp, err := post(cl, "a")
		then.AssertThat(t, err, is.Nil())
		_ = resp.Body.Close()
		then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusForbidden))
		then.AssertThat(t, sap.posts.Load(), is.EqualTo(int32(1)))
	})
	t.Run("custom fetch path", func(t *testing.T) {
		var fetched atomic.Bool
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/csrf" {
				fetched.Store(true)
				w.Header().Set("X-CSRF-Token", "z")
			}
		})
		cl := newCaller(t, h, btpingotest.WithCSRFFetchPath("/csrf"))
		resp, err := post(cl, "a")
		then.AssertThat(t, err, is.Nil())
		_ = resp.Body.Close()
		then.AssertThat(t, fetched.Load(), is.True())
	})
	t.Run("fetch failure surfaces", func(t *testing.T) {
		cl := newCaller(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
		resp, err := post(cl, "a")
		then.AssertThat(t, resp == nil, is.True())
		then.AssertThat(t, err, is.Not(is.Nil()))
	})
}
