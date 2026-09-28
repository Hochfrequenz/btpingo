package btpingo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

// RequestIDHeader is the inbound/outbound HTTP header carrying the
// request ID. Downstream systems (approuter, BTP app-logging) use this
// exact spelling; keeping it as a constant means nobody can change it
// in one place and silently break correlation with the platform.
const RequestIDHeader = "X-Request-Id"

// validRequestIDPattern bounds what an inbound X-Request-Id is trusted
// to carry. RequestIDHeader's own doc comment names the approuter and
// BTP app-logging as the downstream consumers that rely on this
// header's exact spelling for correlation, but that is a claim about
// who READS the header, not evidence that anything upstream validates
// what a caller puts INTO it — and an app may well be reachable
// without an approuter in front of it. Cloud Foundry's own routing
// layer supplies a *different* correlation header (X-Vcap-Request-Id),
// not this one. So a caller-supplied value that fails this pattern is
// treated exactly like an absent one: a fresh ID is generated instead
// of trusting an arbitrary string — bounded only by Go's default 1 MiB
// header limit, with no charset restriction at all — into every log
// line and error envelope for the request.
//
// The character class matches [NewRequestID]'s own output (hex) plus
// the punctuation a UUID or a human-chosen correlation id commonly
// uses, and 64 is generous for any of those while still bounding the
// log-volume amplification an unbounded value would allow.
var validRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidRequestID reports whether id is safe to trust as an inbound
// X-Request-Id: 1-64 characters, restricted to the charset a UUID or a
// hex token uses. A caller-supplied request middleware (e.g.
// ginpingo.RequestID) should fall back to [NewRequestID] when this
// returns false, rather than echoing an arbitrary caller-supplied
// string into logs and error envelopes.
func ValidRequestID(id string) bool {
	return validRequestIDPattern.MatchString(id)
}

// RequestIDFromContext returns the request ID stored on the request
// Context by a request-ID middleware (e.g. ginpingo.RequestID), or ""
// if no such middleware ran. Handlers that need the ID outside a Gin
// context (e.g. a background goroutine they kick off) can read it
// here.
//
// It is what lets a huma (or other non-Gin) error path put
// `request_id` in its error envelope, where there is no Gin context to
// read.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDCtxKey{}).(string)
	return v
}

// ContextWithRequestID returns ctx carrying the given request ID, as a
// request-ID middleware (e.g. ginpingo.RequestID) does for a live
// request.
//
// Exported for the same reason as [ContextWithScopes]: a handler test
// that needs a request-scoped id without standing up the whole
// middleware chain, and any future composer of such a context. The
// production writer is that middleware and nothing else — this does
// not reach the X-Request-Id response header, so a caller that uses it
// outside a test is creating an id no client will ever see.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDCtxKey{}, id)
}

type requestIDCtxKey struct{}

// NewRequestID generates a short hex token suitable as a request ID
// when no valid inbound X-Request-Id is present.
//
// The generated ID is 16 hex chars (8 random bytes) — short enough to
// eyeball, wide enough to be effectively unique within a single
// deployment's log retention. A UUID is fine too; this is only a
// default.
func NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand never errors on supported platforms; if it
		// somehow does, a constant placeholder is safer than
		// panicking a request-handling goroutine.
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}
