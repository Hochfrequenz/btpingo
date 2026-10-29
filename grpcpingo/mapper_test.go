package grpcpingo_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/grpcpingo"
)

func Test_DefaultCodes(t *testing.T) {
	want := map[btpingo.ErrorCode]connect.Code{
		btpingo.CodeInvalidRequest:      connect.CodeInvalidArgument,
		btpingo.CodeUnauthorized:        connect.CodeUnauthenticated,
		btpingo.CodeForbidden:           connect.CodePermissionDenied,
		btpingo.CodeNotFound:            connect.CodeNotFound,
		btpingo.CodeMethodNotAllowed:    connect.CodeUnimplemented,
		btpingo.CodeRequestTooLarge:     connect.CodeResourceExhausted,
		btpingo.CodeUpstreamUnreachable: connect.CodeUnavailable,
		btpingo.CodeInternal:            connect.CodeInternal,
	}
	got := grpcpingo.DefaultCodes()
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for code, c := range want {
		if got[code] != c {
			t.Errorf("%s -> %v, want %v", code, got[code], c)
		}
	}
	got[btpingo.CodeNotFound] = connect.CodeAborted // a fresh map per call: callers may edit it
	if grpcpingo.DefaultCodes()[btpingo.CodeNotFound] != connect.CodeNotFound {
		t.Error("DefaultCodes shares its map between calls")
	}
}

func Test_Mapper_ErrorCarriesCodeMessageAndOneErrorInfo(t *testing.T) {
	m := grpcpingo.Mapper{Domain: testDomain, Codes: grpcpingo.DefaultCodes()}
	for code, want := range grpcpingo.DefaultCodes() {
		cerr := m.Error(code, "some message")
		c, info := errorInfoOf(t, cerr)
		if c != want || info.GetReason() != string(code) || info.GetDomain() != testDomain {
			t.Errorf("%s: code %v reason %q domain %q", code, c, info.GetReason(), info.GetDomain())
		}
		if cerr.Message() != "some message" {
			t.Errorf("message = %q", cerr.Message())
		}
	}
}

func Test_Mapper_NilCodesUsesTheDefaults(t *testing.T) {
	c, info := errorInfoOf(t, grpcpingo.Mapper{Domain: testDomain}.Error(btpingo.CodeForbidden, "x"))
	if c != connect.CodePermissionDenied || info.GetReason() != "forbidden" {
		t.Fatalf("got %v %q", c, info.GetReason())
	}
}

func Test_Mapper_OverrideAndOwnCode(t *testing.T) {
	codes := grpcpingo.DefaultCodes()
	codes[btpingo.CodeNotFound] = connect.CodeFailedPrecondition
	codes["cursor_stale"] = connect.CodeAborted
	m := grpcpingo.Mapper{Domain: testDomain, Codes: codes}
	if c, _ := errorInfoOf(t, m.Error(btpingo.CodeNotFound, "x")); c != connect.CodeFailedPrecondition {
		t.Errorf("override: %v", c)
	}
	if c, info := errorInfoOf(t, m.Error("cursor_stale", "x")); c != connect.CodeAborted || info.GetReason() != "cursor_stale" {
		t.Errorf("own code: %v %q", c, info.GetReason())
	}
}

func Test_Mapper_UnknownCodeIsInternal(t *testing.T) {
	m := grpcpingo.Mapper{Domain: testDomain, Codes: grpcpingo.DefaultCodes()}
	c, info := errorInfoOf(t, m.Error("never_heard_of_it", "x"))
	if c != connect.CodeInternal || info.GetReason() != "internal" {
		t.Fatalf("got %v %q", c, info.GetReason())
	}
}

func Test_Mapper_EmptyDomainPanicsOnFirstUse(t *testing.T) {
	defer func() {
		r := recover()
		if r != "grpcpingo: Mapper needs a non-empty Domain" {
			t.Fatalf("panic = %v", r)
		}
	}()
	grpcpingo.Mapper{}.Error(btpingo.CodeInternal, "x")
}

func Test_Mapper_RecoverReturnsInternalAndLogsOnce(t *testing.T) {
	buf := captureLog(t)
	m := grpcpingo.Mapper{Domain: testDomain}
	err := m.Recover(context.Background(), connect.Spec{}, http.Header{}, "boom at 10.1.2.3")
	c, info := errorInfoOf(t, err)
	if c != connect.CodeInternal || info.GetReason() != "internal" {
		t.Fatalf("got %v %q", c, info.GetReason())
	}
	if strings.Contains(err.Error(), "10.1.2.3") {
		t.Fatalf("panic value reached the error: %v", err)
	}
	log := buf.String()
	if strings.Count(log, `"level":"ERROR"`) != 1 || !strings.Contains(log, "boom at 10.1.2.3") || !strings.Contains(log, "goroutine") {
		t.Fatalf("log = %s", log)
	}
}

func Test_Mapper_RecoverThroughHandlerAnswersEachProtocol(t *testing.T) {
	captureLog(t)
	m := grpcpingo.Mapper{Domain: testDomain}
	mux := http.NewServeMux()
	mux.Handle(unaryPath, panickingUnary(connect.WithRecover(m.Recover)))
	mux.Handle(streamPath, panickingStream(connect.WithRecover(m.Recover)))
	ts := startServer(t, mux)
	eachProtocol(t, func(t *testing.T, proto []connect.ClientOption) {
		c, info := errorInfoOf(t, callUnary(ts, proto, ""))
		if c != connect.CodeInternal || info.GetReason() != "internal" || info.GetDomain() != testDomain {
			t.Errorf("unary: %v %q", c, info.GetReason())
		}
		_, err := callStream(ts, proto, "")
		if c, info := errorInfoOf(t, err); c != connect.CodeInternal || info.GetReason() != "internal" {
			t.Errorf("stream: %v %q", c, info.GetReason())
		}
	})
}
