package btpingotest_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/btpingotest"
)

// newCaller starts a HandlerCaller that is closed with the test.
func newCaller(t *testing.T, h http.Handler, opts ...btpingotest.HandlerCallerOption) *btpingotest.HandlerCaller {
	t.Helper()
	c, err := btpingotest.NewHandlerCaller(h, opts...)
	then.AssertThat(t, err, is.Nil())
	t.Cleanup(c.Close)
	return c
}

type seen struct {
	method, path, query, uri, host, body string
	header                               http.Header
}

func recordingHandler(out *seen) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*out = seen{r.Method, r.URL.Path, r.URL.RawQuery, r.RequestURI, r.Host, string(b), r.Header.Clone()}
		w.Header().Set("X-Answer", "42")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	})
}

func Test_HandlerCaller_RequestReachesHandlerIntact(t *testing.T) {
	var got seen
	c := newCaller(t, recordingHandler(&got))
	h := http.Header{}
	h.Set("X-Custom", "a")
	h.Add("X-Multi", "1")
	h.Add("X-Multi", "2")
	h.Set("Accept", "application/json")

	resp, err := c.CallOnPremise(context.Background(), "SAP", http.MethodPost, "/sap/zeit/v1/x?a=1&b=2", h, strings.NewReader(`{"k":"v"}`))
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()

	then.AssertThat(t, got.method, is.EqualTo(http.MethodPost))
	then.AssertThat(t, got.path, is.EqualTo("/sap/zeit/v1/x"))
	then.AssertThat(t, got.query, is.EqualTo("a=1&b=2"))
	then.AssertThat(t, got.uri, is.EqualTo("/sap/zeit/v1/x?a=1&b=2"))
	then.AssertThat(t, got.body, is.EqualTo(`{"k":"v"}`))
	then.AssertThat(t, got.header.Get("X-Custom"), is.EqualTo("a"))
	then.AssertThat(t, strings.Join(got.header.Values("X-Multi"), ","), is.EqualTo("1,2"))
	then.AssertThat(t, got.header.Get("Accept"), is.EqualTo("application/json"))

	then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusCreated))
	then.AssertThat(t, resp.Header.Get("X-Answer"), is.EqualTo("42"))
	b, err := io.ReadAll(resp.Body)
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, string(b), is.EqualTo("hello"))
}

func Test_HandlerCaller_PathSuffixForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/a/b", "/a/b"},
		{"a/b", "/a/b"},
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			var got seen
			cl := newCaller(t, recordingHandler(&got))
			resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, c.in, nil, nil)
			then.AssertThat(t, err, is.Nil())
			_ = resp.Body.Close()
			want := c.want
			if want == "" {
				want = "/" // an empty request path is "/" on a server
			}
			then.AssertThat(t, got.path, is.EqualTo(want))
		})
	}
}

func Test_HandlerCaller_RejectsLikeService(t *testing.T) {
	c := newCaller(t, http.NotFoundHandler())
	for _, p := range []string{"/a/../b", "/a/%2e%2e/b", "/a%20b"} {
		t.Run(p, func(t *testing.T) {
			resp, err := c.CallOnPremise(context.Background(), "SAP", http.MethodGet, p, nil, nil)
			then.AssertThat(t, resp == nil, is.True())
			then.AssertThat(t, err, is.Not(is.Nil()))
		})
	}
}

func Test_HandlerCaller_HeaderFiltering(t *testing.T) {
	cases := []struct {
		name    string
		in      http.Header
		present map[string]string
		absent  []string
	}{
		{
			name: "dropped and kept",
			in: http.Header{
				"Authorization":       {"Bearer inbound"},
				"Proxy-Authorization": {"x"},
				"Connection":          {"keep-alive"},
				"Keep-Alive":          {"1"},
				"Te":                  {"trailers"},
				"Transfer-Encoding":   {"chunked"},
				"Upgrade":             {"h2c"},
				"Host":                {"evil.example"},
				"X-Keep":              {"yes"},
			},
			present: map[string]string{"X-Keep": "yes"},
			absent:  []string{"Authorization", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Transfer-Encoding", "Upgrade"},
		},
		{
			name:    "cookies reduced to SAP session cookies",
			in:      http.Header{"Cookie": {"JSESSIONID=abc; SAP_SESSIONID_ABC_100=s; sap-usercontext=c; track=1"}},
			present: map[string]string{"Cookie": "SAP_SESSIONID_ABC_100=s; sap-usercontext=c"},
		},
		{
			name:   "cookie header without SAP cookies disappears",
			in:     http.Header{"Cookie": {"JSESSIONID=abc"}},
			absent: []string{"Cookie"},
		},
		{
			name:    "caller user-agent wins",
			in:      http.Header{"User-Agent": {"my-client/1"}},
			present: map[string]string{"User-Agent": "my-client/1"},
		},
		{
			name:    "default user-agent",
			in:      nil,
			present: map[string]string{"User-Agent": btpingo.DefaultUserAgent},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got seen
			cl := newCaller(t, recordingHandler(&got))
			resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/x", c.in, nil)
			then.AssertThat(t, err, is.Nil())
			_ = resp.Body.Close()
			for k, v := range c.present {
				then.AssertThat(t, got.header.Get(k), is.EqualTo(v))
			}
			for _, k := range c.absent {
				then.AssertThat(t, len(got.header.Values(k)), is.EqualTo(0))
			}
			then.AssertThat(t, strings.HasPrefix(got.host, "127.0.0.1:"), is.True())
			then.AssertThat(t, len(got.header.Values("Host")), is.EqualTo(0))
		})
	}
}

func Test_HandlerCaller_UserAgentOption(t *testing.T) {
	var got seen
	cl := newCaller(t, recordingHandler(&got), btpingotest.WithUserAgent("svc/9"))
	resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	_ = resp.Body.Close()
	then.AssertThat(t, got.header.Get("User-Agent"), is.EqualTo("svc/9"))
}

func Test_HandlerCaller_ResponseSizeLimit(t *testing.T) {
	big := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 11)))
	})
	cases := []struct {
		name    string
		opts    []btpingotest.HandlerCallerOption
		wantErr bool
	}{
		{"over limit", []btpingotest.HandlerCallerOption{btpingotest.WithResponseSizeLimit(10)}, true},
		{"exactly at limit", []btpingotest.HandlerCallerOption{btpingotest.WithResponseSizeLimit(11)}, false},
		{"default limit is large", nil, false},
		{"non-positive keeps default", []btpingotest.HandlerCallerOption{btpingotest.WithResponseSizeLimit(0)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl := newCaller(t, big, c.opts...)
			resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/x", nil, nil)
			then.AssertThat(t, err, is.Nil())
			defer func() { _ = resp.Body.Close() }()
			_, err = io.ReadAll(resp.Body)
			if c.wantErr {
				then.AssertThat(t, errors.Is(err, btpingo.ErrOnPremResponseTooLarge), is.True())
				return
			}
			then.AssertThat(t, err, is.Nil())
		})
	}
}

func Test_HandlerCaller_DefaultLimitIsLibraryDefault(t *testing.T) {
	over := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, btpingo.DefaultOnPremResponseSizeLimit+1))
	})
	resp, err := newCaller(t, over).CallOnPremise(context.Background(), "SAP", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	_, err = io.ReadAll(resp.Body)
	then.AssertThat(t, errors.Is(err, btpingo.ErrOnPremResponseTooLarge), is.True())
}

func Test_HandlerCaller_Destination(t *testing.T) {
	cases := []struct {
		name    string
		opts    []btpingotest.HandlerCallerOption
		dest    string
		wantErr bool
	}{
		{"default name", nil, btpingotest.DefaultDestinationName, false},
		{"default name, wrong call", nil, "OTHER", true},
		{"custom name", []btpingotest.HandlerCallerOption{btpingotest.WithDestinationName("ZR")}, "ZR", false},
		{"custom name, default used", []btpingotest.HandlerCallerOption{btpingotest.WithDestinationName("ZR")}, btpingotest.DefaultDestinationName, true},
		{"case matters", []btpingotest.HandlerCallerOption{btpingotest.WithDestinationName("ZR")}, "zr", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			called := false
			h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
			cl := newCaller(t, h, c.opts...)
			resp, err := cl.CallOnPremise(context.Background(), c.dest, http.MethodGet, "/x", nil, nil)
			if c.wantErr {
				then.AssertThat(t, errors.Is(err, btpingo.ErrDestinationNotFound), is.True())
				then.AssertThat(t, called, is.False())
				kind, _ := btpingo.ClassifyOnPremError(err)
				then.AssertThat(t, kind, is.EqualTo(btpingo.OnPremFailureDestinationNotFound))
				return
			}
			then.AssertThat(t, err, is.Nil())
			_ = resp.Body.Close()
			then.AssertThat(t, called, is.True())
		})
	}
}

func Test_HandlerCaller_TransportFailure(t *testing.T) {
	boom := errors.New("connection refused")
	t.Run("every call", func(t *testing.T) {
		called := false
		cl := newCaller(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
			btpingotest.WithTransportFault(func(*http.Request) error { return boom }))
		resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/x", nil, nil)
		then.AssertThat(t, resp == nil, is.True())
		then.AssertThat(t, errors.Is(err, boom), is.True())
		then.AssertThat(t, called, is.False())
		kind, _ := btpingo.ClassifyOnPremError(err)
		then.AssertThat(t, kind, is.EqualTo(btpingo.OnPremFailureTransport))
	})
	t.Run("per request", func(t *testing.T) {
		cl := newCaller(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			btpingotest.WithTransportFault(func(r *http.Request) error {
				if r.URL.Path == "/down" {
					return boom
				}
				return nil
			}))
		_, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/down", nil, nil)
		then.AssertThat(t, errors.Is(err, boom), is.True())
		resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/up", nil, nil)
		then.AssertThat(t, err, is.Nil())
		_ = resp.Body.Close()
	})
}

func Test_HandlerCaller_Context(t *testing.T) {
	t.Run("handler blocking on request context returns when ctx ends", func(t *testing.T) {
		returned := make(chan struct{})
		h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
			close(returned)
		})
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		resp, err := newCaller(t, h).CallOnPremise(ctx, "SAP", http.MethodGet, "/x", nil, nil)
		then.AssertThat(t, resp == nil, is.True())
		then.AssertThat(t, errors.Is(err, context.DeadlineExceeded), is.True())
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not observe ctx cancellation")
		}
	})
	t.Run("cancel while handler runs", func(t *testing.T) {
		started := make(chan struct{})
		h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		})
		ctx, cancel := context.WithCancel(context.Background())
		go func() { <-started; cancel() }()
		_, err := newCaller(t, h).CallOnPremise(ctx, "SAP", http.MethodGet, "/x", nil, nil)
		then.AssertThat(t, errors.Is(err, context.Canceled), is.True())
	})
	t.Run("handler ignoring ctx does not hang the caller", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release })
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, err := newCaller(t, h).CallOnPremise(ctx, "SAP", http.MethodGet, "/x", nil, nil)
		then.AssertThat(t, errors.Is(err, context.DeadlineExceeded), is.True())
	})
	t.Run("already cancelled", func(t *testing.T) {
		called := false
		h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := newCaller(t, h).CallOnPremise(ctx, "SAP", http.MethodGet, "/x", nil, nil)
		then.AssertThat(t, errors.Is(err, context.Canceled), is.True())
		then.AssertThat(t, called, is.False())
	})
}

func Test_HandlerCaller_HandlerPanicAndGoexitAreTransportErrors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"panic":                func(http.ResponseWriter, *http.Request) { panic("kaputt") },
		"runtime.Goexit":       func(http.ResponseWriter, *http.Request) { runtime.Goexit() },
		"http.ErrAbortHandler": func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			type res struct {
				resp *http.Response
				err  error
			}
			ch := make(chan res, 1)
			cl := newCaller(t, h)
			go func() {
				resp, err := cl.CallOnPremise(context.Background(), "SAP", http.MethodGet, "/x", nil, nil)
				ch <- res{resp, err}
			}()
			select {
			case r := <-ch:
				then.AssertThat(t, r.resp == nil, is.True())
				then.AssertThat(t, r.err, is.Not(is.Nil()))
				kind, _ := btpingo.ClassifyOnPremError(r.err)
				then.AssertThat(t, kind, is.EqualTo(btpingo.OnPremFailureTransport))
			case <-time.After(10 * time.Second):
				t.Fatal("CallOnPremise hangs")
			}
		})
	}
}

func Test_HandlerCaller_NoBodyAndImplicitStatus(t *testing.T) {
	var n int64 = -2
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n = r.ContentLength
		_, _ = w.Write([]byte("ok"))
	})
	resp, err := newCaller(t, h).CallOnPremise(context.Background(), "SAP", http.MethodGet, "/x", nil, nil)
	then.AssertThat(t, err, is.Nil())
	_ = resp.Body.Close()
	then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusOK))
	then.AssertThat(t, n, is.EqualTo(int64(0)))
}
