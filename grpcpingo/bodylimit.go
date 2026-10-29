package grpcpingo

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/hochfrequenz/btpingo"
)

// MaxBodySize refuses a call whose Content-Length exceeds limit bytes with
// ResourceExhausted and the ErrorInfo reason "request_too_large" (answered in
// the protocol of the request, not logged), and caps every other body at limit
// bytes with [http.MaxBytesReader].
//
// A body without a Content-Length (chunked HTTP/1.1, HTTP/2) cannot be refused
// up front. Pair MaxBodySize with connect.WithReadMaxBytes(limit) on the
// handler: connect-go then rejects it with ResourceExhausted as well, though
// without an ErrorInfo. A compressed message is checked after decompression by
// the same option.
//
// Put [Auth] before MaxBodySize, so an unauthenticated caller learns about the
// credentials and not about the size limit.
func MaxBodySize(limit int64, m Mapper) func(http.Handler) http.Handler {
	errW := connect.NewErrorWriter()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				// a failed write means the client is gone: nothing left to tell it
				_ = errW.Write(w, r, m.Error(btpingo.CodeRequestTooLarge, "request body exceeds size limit"))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}
