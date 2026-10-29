package grpcpingo_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/grpcpingo"
)

// fakeParser accepts the tokens of its map and refuses everything else with an error that
// carries internal detail.
type fakeParser map[string]jwt.MapClaims

func (p fakeParser) Parse(raw string) (jwt.MapClaims, error) {
	if c, ok := p[raw]; ok {
		return c, nil
	}
	return nil, errors.New("signature is invalid: kid abc not found at 10.1.2.3")
}

var tokens = fakeParser{
	"good":    {"client_id": "sb-caller", "scope": []any{testScope}},
	"noscope": {"client_id": "sb-caller", "scope": []any{"other!t1.User"}},
}

var mapper = grpcpingo.Mapper{Domain: testDomain}

func guarded(opts ...grpcpingo.AuthOption) http.Handler {
	return grpcpingo.Auth(tokens, testScope, mapper, opts...)(serviceMux(nil))
}

func Test_Auth_RejectionsAnswerEachProtocolWithCodeAndErrorInfo(t *testing.T) {
	captureLog(t)
	tests := []struct {
		name   string
		token  string
		code   connect.Code
		reason string
	}{
		{"no token", "", connect.CodeUnauthenticated, "unauthorized"},
		{"invalid token", "bad", connect.CodeUnauthenticated, "unauthorized"},
		{"token without the scope", "noscope", connect.CodePermissionDenied, "forbidden"},
	}
	ts := startServer(t, guarded())
	eachProtocol(t, func(t *testing.T, proto []connect.ClientOption) {
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := callUnary(ts, proto, tc.token)
				c, info := errorInfoOf(t, err)
				if c != tc.code || info.GetReason() != tc.reason || info.GetDomain() != testDomain {
					t.Errorf("got %v %q %q, want %v %q", c, info.GetReason(), info.GetDomain(), tc.code, tc.reason)
				}
				if strings.Contains(err.Error(), "10.1.2.3") {
					t.Errorf("parse error reached the client: %v", err)
				}
			})
		}
	})
}

// A streaming call fails the same way: the status arrives on the stream, no message before it.
func Test_Auth_StreamingCallGetsTheStatusOnTheStream(t *testing.T) {
	captureLog(t)
	ts := startServer(t, guarded())
	eachProtocol(t, func(t *testing.T, proto []connect.ClientOption) {
		n, err := callStream(ts, proto, "")
		if n != 0 {
			t.Errorf("messages = %d, want 0", n)
		}
		c, info := errorInfoOf(t, err)
		if c != connect.CodeUnauthenticated || info.GetReason() != string(btpingo.CodeUnauthorized) {
			t.Errorf("got %v %q", c, info.GetReason())
		}
	})
}

func Test_Auth_ValidTokenReachesTheHandlerOnEachProtocol(t *testing.T) {
	ts := startServer(t, guarded())
	eachProtocol(t, func(t *testing.T, proto []connect.ClientOption) {
		if err := callUnary(ts, proto, "good"); err != nil {
			t.Errorf("unary: %v", err)
		}
		if n, err := callStream(ts, proto, "good"); err != nil || n != 1 {
			t.Errorf("stream: %d messages, err %v", n, err)
		}
	})
}

func Test_Auth_PutsScopesAndTokenIntoTheRequestContext(t *testing.T) {
	var got context.Context
	h := grpcpingo.Auth(tokens, testScope, mapper)(serviceMux(func(ctx context.Context) { got = ctx }))
	ts := startServer(t, h)
	if err := callUnary(ts, nil, "good"); err != nil {
		t.Fatal(err)
	}
	if !btpingo.HasScope(got, testScope) {
		t.Error("scope not in the request context")
	}
	if raw, _ := got.Value(btpingo.ForwardedUserTokenKey{}).(string); raw != "good" {
		t.Errorf("forwarded token = %q, want good", raw)
	}
}

func Test_Auth_WithContextFromClaimsRunsAfterTheScopeCheck(t *testing.T) {
	type ctxKey struct{}
	var calls atomic.Int32
	var got context.Context
	h := grpcpingo.Auth(tokens, testScope, mapper,
		grpcpingo.WithContextFromClaims(func(ctx context.Context, c jwt.MapClaims) context.Context {
			calls.Add(1)
			return context.WithValue(ctx, ctxKey{}, c["client_id"])
		}))(serviceMux(func(ctx context.Context) { got = ctx }))
	ts := startServer(t, h)
	captureLog(t)

	_ = callUnary(ts, nil, "noscope") // rejected: the hook must not run
	_ = callUnary(ts, nil, "bad")
	_ = callUnary(ts, nil, "")
	if calls.Load() != 0 {
		t.Fatalf("hook ran %d times for rejected calls", calls.Load())
	}
	if err := callUnary(ts, nil, "good"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || got.Value(ctxKey{}) != "sb-caller" {
		t.Fatalf("hook calls = %d, value = %v", calls.Load(), got.Value(ctxKey{}))
	}
	if !btpingo.HasScope(got, testScope) {
		t.Error("hook context lost the scopes")
	}
}

func Test_Auth_EmptyScopePanicsAtConstruction(t *testing.T) {
	defer func() {
		if r := recover(); r != "grpcpingo: Auth needs a non-empty scope" {
			t.Fatalf("panic = %v", r)
		}
	}()
	grpcpingo.Auth(tokens, "", mapper)
}

func Test_Auth_NonBearerSchemeIsRejected(t *testing.T) {
	ts := startServer(t, guarded())
	req, _ := http.NewRequest(http.MethodPost, ts.URL+unaryPath, nil)
	req.Header.Set("Authorization", "Basic good")
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a non-Bearer scheme", resp.StatusCode)
	}
}

// As ginpingo.AbortError on a JSON route: a missing token and a missing scope are routine and not
// logged; an invalid token is, once, at ERROR, with its parse error.
func Test_Auth_LogsOnlyAnInvalidToken(t *testing.T) {
	ts := startServer(t, guarded())
	for name, token := range map[string]string{"no token": "", "no scope": "noscope", "valid": "good"} {
		t.Run(name, func(t *testing.T) {
			buf := captureLog(t)
			_ = callUnary(ts, nil, token)
			if buf.String() != "" {
				t.Fatalf("log = %s", buf.String())
			}
		})
	}
	t.Run("invalid token", func(t *testing.T) {
		buf := captureLog(t)
		_ = callUnary(ts, nil, "bad")
		log := buf.String()
		if strings.Count(log, `"level":"ERROR"`) != 1 || !strings.Contains(log, "10.1.2.3") {
			t.Fatalf("log = %s", log)
		}
	})
}

// A request that is not a connect call at all still gets a rejection, not a panic.
func Test_Auth_PlainHTTPRequestIsRejected(t *testing.T) {
	h := guarded()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code < 400 {
		t.Fatalf("status = %d", w.Code)
	}
}

func Test_Auth_EmptyDomainPanicsAtConstruction(t *testing.T) {
	defer func() {
		if r := recover(); r != emptyDomainPanic {
			t.Fatalf("panic = %v", r)
		}
	}()
	grpcpingo.Auth(tokens, testScope, grpcpingo.Mapper{})
}

// "Bearer " with nothing behind it is a missing token: routine, so unlogged.
func Test_Auth_EmptyBearerTokenIsMissingNotInvalid(t *testing.T) {
	buf := captureLog(t)
	// a parser that would accept the empty token proves the check is not left to it
	h := grpcpingo.Auth(fakeParser{"": {"scope": []any{testScope}}}, testScope, mapper)(serviceMux(nil))
	ts := startServer(t, h)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+unaryPath, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer ")
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if buf.String() != "" {
		t.Fatalf("log = %s", buf.String())
	}
}

// The log carries the gRPC code the client actually gets, also when Codes overrides a mapping.
func Test_Auth_LogsTheMappedGRPCCode(t *testing.T) {
	buf := captureLog(t)
	m := grpcpingo.Mapper{Domain: testDomain, Codes: grpcpingo.DefaultCodes()}
	m.Codes[btpingo.CodeUnauthorized] = connect.CodePermissionDenied
	ts := startServer(t, grpcpingo.Auth(tokens, testScope, m)(serviceMux(nil)))
	c, info := errorInfoOf(t, callUnary(ts, nil, "bad"))
	if c != connect.CodePermissionDenied || info.GetReason() != string(btpingo.CodeUnauthorized) {
		t.Fatalf("client got %v %q", c, info.GetReason())
	}
	if !strings.Contains(buf.String(), `"grpc_code":"permission_denied"`) {
		t.Fatalf("log = %s", buf.String())
	}
}

// Native gRPC clients speak HTTP/2, where the status travels in real trailers: the rejection must
// arrive there on every protocol, for a unary and a streaming call.
func Test_Auth_RejectionsOverHTTP2(t *testing.T) {
	captureLog(t)
	var protoMajor atomic.Int32
	h := grpcpingo.Auth(tokens, testScope, mapper)(serviceMux(nil))
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protoMajor.Store(int32(r.ProtoMajor))
		h.ServeHTTP(w, r)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	eachProtocol(t, func(t *testing.T, proto []connect.ClientOption) {
		c, info := errorInfoOf(t, callUnary(ts, proto, ""))
		if c != connect.CodeUnauthenticated || info.GetReason() != string(btpingo.CodeUnauthorized) {
			t.Errorf("unary: %v %q", c, info.GetReason())
		}
		n, err := callStream(ts, proto, "")
		c, info = errorInfoOf(t, err)
		if n != 0 || c != connect.CodeUnauthenticated || info.GetReason() != string(btpingo.CodeUnauthorized) {
			t.Errorf("stream: %d messages, %v %q", n, c, info.GetReason())
		}
		if err := callUnary(ts, proto, "good"); err != nil {
			t.Errorf("valid call: %v", err)
		}
		if protoMajor.Load() != 2 {
			t.Errorf("served over HTTP/%d, want 2", protoMajor.Load())
		}
	})
}
