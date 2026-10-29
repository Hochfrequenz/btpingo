package grpcpingo_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	testDomain       = "myservice.example.com"
	testScope        = "myapp!t1.User"
	emptyDomainPanic = "grpcpingo: Mapper needs a non-empty Domain"
	unaryPath        = "/test.v1.TestService/Unary"
	streamPath       = "/test.v1.TestService/Stream"
)

// syncBuf is a log sink that tests can read while the server still writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLog routes the default slog logger into a buffer for the test.
func captureLog(t *testing.T) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

// protocols are the three wire protocols connect-go speaks; Connect is the client default.
var protocols = map[string][]connect.ClientOption{
	"grpc":     {connect.WithGRPC()},
	"grpc-web": {connect.WithGRPCWeb()},
	"connect":  nil,
}

func eachProtocol(t *testing.T, f func(t *testing.T, proto []connect.ClientOption)) {
	t.Helper()
	for name, proto := range protocols {
		t.Run(name, func(t *testing.T) { f(t, proto) })
	}
}

// serviceMux serves one unary and one server-streaming procedure on emptypb.Empty (no codegen).
// seen, when non-nil, is called with the request context inside both handlers.
func serviceMux(seen func(context.Context), hopts ...connect.HandlerOption) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle(unaryPath, connect.NewUnaryHandler(unaryPath,
		func(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			if seen != nil {
				seen(ctx)
			}
			return connect.NewResponse(&emptypb.Empty{}), nil
		}, hopts...))
	mux.Handle(streamPath, connect.NewServerStreamHandler(streamPath,
		func(ctx context.Context, _ *connect.Request[emptypb.Empty], s *connect.ServerStream[emptypb.Empty]) error {
			if seen != nil {
				seen(ctx)
			}
			return s.Send(&emptypb.Empty{})
		}, hopts...))
	return mux
}

func panickingUnary(opts ...connect.HandlerOption) http.Handler {
	return connect.NewUnaryHandler(unaryPath,
		func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			panic("boom at 10.1.2.3")
		}, opts...)
}

func panickingStream(opts ...connect.HandlerOption) http.Handler {
	return connect.NewServerStreamHandler(streamPath,
		func(context.Context, *connect.Request[emptypb.Empty], *connect.ServerStream[emptypb.Empty]) error {
			panic("boom at 10.1.2.3")
		}, opts...)
}

func startServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func callUnary(ts *httptest.Server, proto []connect.ClientOption, token string) error {
	c := connect.NewClient[emptypb.Empty, emptypb.Empty](ts.Client(), ts.URL+unaryPath, proto...)
	req := connect.NewRequest(&emptypb.Empty{})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	_, err := c.CallUnary(context.Background(), req)
	return err
}

// callStream opens the stream and drains it, returning the error that ends it.
func callStream(ts *httptest.Server, proto []connect.ClientOption, token string) (messages int, err error) {
	c := connect.NewClient[emptypb.Empty, emptypb.Empty](ts.Client(), ts.URL+streamPath, proto...)
	req := connect.NewRequest(&emptypb.Empty{})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	s, err := c.CallServerStream(context.Background(), req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = s.Close() }()
	for s.Receive() {
		messages++
	}
	return messages, s.Err()
}

// errorInfoOf returns the one ErrorInfo of err, failing when there is not exactly one.
func errorInfoOf(t *testing.T, err error) (connect.Code, *errdetails.ErrorInfo) {
	t.Helper()
	cerr, ok := err.(*connect.Error)
	if !ok {
		t.Fatalf("error is %T (%v), want *connect.Error", err, err)
	}
	if len(cerr.Details()) != 1 {
		t.Fatalf("details = %d, want exactly one ErrorInfo (err: %v)", len(cerr.Details()), err)
	}
	msg, verr := cerr.Details()[0].Value()
	if verr != nil {
		t.Fatalf("detail value: %v", verr)
	}
	info, ok := msg.(*errdetails.ErrorInfo)
	if !ok {
		t.Fatalf("detail is %T, want *errdetails.ErrorInfo", msg)
	}
	return cerr.Code(), info
}
