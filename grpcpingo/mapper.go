package grpcpingo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/hochfrequenz/btpingo"
)

// DefaultCodes returns the gRPC code of each canonical [btpingo.ErrorCode].
// The map is new on every call: add your own codes or change a mapping, then
// pass it as [Mapper].Codes.
//
//	invalid_request      InvalidArgument
//	unauthorized         Unauthenticated
//	forbidden            PermissionDenied
//	not_found            NotFound
//	method_not_allowed   Unimplemented
//	request_too_large    ResourceExhausted
//	upstream_unreachable Unavailable
//	internal             Internal
func DefaultCodes() map[btpingo.ErrorCode]connect.Code {
	return map[btpingo.ErrorCode]connect.Code{
		btpingo.CodeInvalidRequest:      connect.CodeInvalidArgument,
		btpingo.CodeUnauthorized:        connect.CodeUnauthenticated,
		btpingo.CodeForbidden:           connect.CodePermissionDenied,
		btpingo.CodeNotFound:            connect.CodeNotFound,
		btpingo.CodeMethodNotAllowed:    connect.CodeUnimplemented,
		btpingo.CodeRequestTooLarge:     connect.CodeResourceExhausted,
		btpingo.CodeUpstreamUnreachable: connect.CodeUnavailable,
		btpingo.CodeInternal:            connect.CodeInternal,
	}
}

// Mapper turns a [btpingo.ErrorCode] into a connect error: the gRPC code from
// Codes and exactly one google.rpc.ErrorInfo detail whose reason is the
// public code, so a client switches on the reason as it would on `code` of
// the JSON envelope. The zero value of Codes means [DefaultCodes].
//
// Domain is the ErrorInfo domain, usually the name of the service, for
// example "myservice.example.com". It is required: [Auth] and [MaxBodySize]
// panic at construction when it is empty, and so does [Mapper.Error].
type Mapper struct {
	Domain string
	Codes  map[btpingo.ErrorCode]connect.Code
}

// Error returns the connect error for code with msg as its message. msg
// reaches the client: keep it fixed and free of internal detail. A code that
// Codes does not know becomes Internal with reason "internal"; the code is
// never invented as a status.
func (m Mapper) Error(code btpingo.ErrorCode, msg string) *connect.Error {
	m.mustHaveDomain()
	codes := m.Codes
	if codes == nil {
		codes = DefaultCodes()
	}
	c, ok := codes[code]
	if !ok {
		code, c, msg = btpingo.CodeInternal, connect.CodeInternal, "internal error"
	}
	cerr := connect.NewError(c, errors.New(msg))
	if d, err := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: string(code), Domain: m.Domain}); err == nil {
		cerr.AddDetail(d)
	}
	return cerr
}

// Recover is a [connect.WithRecover] handler: a panic in a handler becomes an
// Internal error with ErrorInfo. The panic value and the stack go to the log
// once, at ERROR level, and never to the client.
//
//	connect.WithRecover(m.Recover)
//
// connect-go itself re-panics http.ErrAbortHandler before calling Recover.
func (m Mapper) Recover(ctx context.Context, _ connect.Spec, _ http.Header, panicValue any) error {
	slog.ErrorContext(ctx, "rpc handler panic",
		"code", string(btpingo.CodeInternal),
		"request_id", btpingo.RequestIDFromContext(ctx),
		"panic", fmt.Sprint(panicValue),
		"stack", string(debug.Stack()),
	)
	return m.Error(btpingo.CodeInternal, "internal error")
}

// mustHaveDomain panics on an empty Domain. [Auth] and [MaxBodySize] call it at
// construction: an error built later, inside a request, would panic outside
// connect's recover and reset the connection instead of answering.
func (m Mapper) mustHaveDomain() {
	if m.Domain == "" {
		panic("grpcpingo: Mapper needs a non-empty Domain")
	}
}
