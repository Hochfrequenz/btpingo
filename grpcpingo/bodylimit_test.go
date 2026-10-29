package grpcpingo_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hochfrequenz/btpingo/grpcpingo"
)

const bodyLimit = 64

// echoMux serves a unary procedure whose request carries a string, so a test can make it big.
func echoMux(opts ...connect.HandlerOption) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(unaryPath, connect.NewUnaryHandler(unaryPath,
		func(_ context.Context, req *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
			return connect.NewResponse(req.Msg), nil
		}, opts...))
	return mux
}

func callEcho(ts *httptest.Server, proto []connect.ClientOption, size int) error {
	c := connect.NewClient[wrapperspb.StringValue, wrapperspb.StringValue](ts.Client(), ts.URL+unaryPath, proto...)
	_, err := c.CallUnary(context.Background(), connect.NewRequest(wrapperspb.String(strings.Repeat("x", size))))
	return err
}

func Test_MaxBodySize_ContentLengthOverTheLimitIsResourceExhaustedWithErrorInfo(t *testing.T) {
	captureLog(t)
	ts := startServer(t, grpcpingo.MaxBodySize(bodyLimit, mapper)(echoMux(connect.WithReadMaxBytes(bodyLimit))))
	eachProtocol(t, func(t *testing.T, proto []connect.ClientOption) {
		if err := callEcho(ts, proto, 10); err != nil {
			t.Fatalf("small message: %v", err)
		}
		c, info := errorInfoOf(t, callEcho(ts, proto, 500))
		if c != connect.CodeResourceExhausted || info.GetReason() != "request_too_large" || info.GetDomain() != testDomain {
			t.Errorf("got %v %q %q", c, info.GetReason(), info.GetDomain())
		}
	})
}

func Test_MaxBodySize_RejectionIsNotLogged(t *testing.T) {
	buf := captureLog(t)
	ts := startServer(t, grpcpingo.MaxBodySize(bodyLimit, mapper)(echoMux()))
	_ = callEcho(ts, nil, 500)
	if buf.String() != "" {
		t.Fatalf("log = %s", buf.String())
	}
}

// Without a Content-Length (chunked HTTP/1.1, HTTP/2) connect-go's own read limit applies: the code is
// right, the error carries no ErrorInfo. This is why the doc says to pair MaxBodySize with
// connect.WithReadMaxBytes.
func Test_MaxBodySize_ChunkedBodyHitsTheReadLimit(t *testing.T) {
	captureLog(t)
	ts := startServer(t, grpcpingo.MaxBodySize(bodyLimit, mapper)(echoMux(connect.WithReadMaxBytes(bodyLimit))))
	body := `"` + strings.Repeat("x", 500) + `"`
	req, err := http.NewRequest(http.MethodPost, ts.URL+unaryPath, io.NopCloser(bytes.NewReader([]byte(body))))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(out), "resource_exhausted") {
		t.Fatalf("status %d body %s", resp.StatusCode, out)
	}
}

// The body is capped even when the wrapped handler sets no limit of its own.
func Test_MaxBodySize_CapsABodyWithoutContentLength(t *testing.T) {
	var readErr error
	h := grpcpingo.MaxBodySize(bodyLimit, mapper)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader(strings.Repeat("x", 500))))
	req.ContentLength = -1
	h.ServeHTTP(httptest.NewRecorder(), req)
	var tooBig *http.MaxBytesError
	if !errors.As(readErr, &tooBig) || tooBig.Limit != bodyLimit {
		t.Fatalf("read error = %v, want *http.MaxBytesError with limit %d", readErr, bodyLimit)
	}
}

func Test_MaxBodySize_BodyAtTheLimitPasses(t *testing.T) {
	called := false
	h := grpcpingo.MaxBodySize(bodyLimit, mapper)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		b, err := io.ReadAll(r.Body)
		if err != nil || len(b) != bodyLimit {
			t.Errorf("read %d bytes, err %v", len(b), err)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", bodyLimit))))
	if !called {
		t.Fatal("handler not called")
	}
}

// Auth before MaxBodySize: an unauthenticated caller learns about the credentials, not the size limit.
func Test_MaxBodySize_BehindAuthAnswersAnOversizedUnauthenticatedCallWithUnauthenticated(t *testing.T) {
	captureLog(t)
	h := grpcpingo.Auth(tokens, testScope, mapper)(grpcpingo.MaxBodySize(bodyLimit, mapper)(echoMux()))
	ts := startServer(t, h)
	c, _ := errorInfoOf(t, callEcho(ts, nil, 500))
	if c != connect.CodeUnauthenticated {
		t.Fatalf("code = %v", c)
	}
}
