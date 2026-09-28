package btpingo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// RequestIDHeader is the inbound/outbound HTTP header carrying the
// request ID. Downstream systems (approuter, BTP app-logging) use this
// exact spelling; keeping it as a constant means nobody can change it
// in one place and silently break correlation with the platform.
const RequestIDHeader = "X-Request-Id"

// RequestIDContextKey is the Gin context key under which the middleware
// stashes the request ID. `AbortError` reads it via c.Get("request_id")
// to populate the error envelope; handlers that want to annotate their
// slog lines with the request ID should do the same.
//
// This is a string because Gin's c.Set/c.Get map uses string keys.
// The context.Context propagation path uses a separately-defined
// typed key (requestIDCtxKey{}) — that's the canonical Go pattern for
// ctx.Value to avoid cross-package collisions (go vet / staticcheck
// flag string keys on context.WithValue).
const RequestIDContextKey = "request_id"

// validRequestID bounds what an inbound X-Request-Id is trusted to
// carry. RequestIDHeader's own doc comment names the approuter and
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
// The character class matches [newRequestID]'s own output (hex) plus
// the punctuation a UUID or a human-chosen correlation id commonly
// uses, and 64 is generous for any of those while still bounding the
// log-volume amplification an unbounded value would allow.
var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// RequestID reads an existing X-Request-Id header or generates a
// short hex token, stashes it in the Gin context under
// RequestIDContextKey, and echoes it back in the response. Installing
// this on the top-level router means every handler, every error
// envelope, and the access log share one correlation ID.
//
// The generated ID is 16 hex chars (8 random bytes) — short enough to
// eyeball, wide enough to be effectively unique within a single
// deployment's log retention. A UUID is fine too; this is only a
// default, and an inbound ID of either shape is kept.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader(RequestIDHeader)
		if rid == "" || !validRequestID.MatchString(rid) {
			rid = newRequestID()
		}
		c.Set(RequestIDContextKey, rid)
		c.Writer.Header().Set(RequestIDHeader, rid)
		// Also propagate through the request context so handlers using
		// slog.InfoContext pick it up if they wire an slog handler that
		// reads the value (not every service does, but making the
		// value reachable from ctx means it is there when they do).
		ctx := context.WithValue(c.Request.Context(), requestIDCtxKey{}, rid)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// RequestIDFromContext returns the request ID stored by the RequestID
// middleware on the request Context, or "" if the middleware isn't in
// the chain. Handlers that need the ID outside a Gin context (e.g. a
// background goroutine they kick off) can read it here.
//
// It is what lets a huma (or other non-Gin) error path put
// `request_id` in its error envelope, where there is no Gin context to
// read. The value is the same string [RequestID] wrote to the
// X-Request-Id response header, which is the property that makes the
// id worth carrying at all.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDCtxKey{}).(string)
	return v
}

// ContextWithRequestID returns ctx carrying the given request ID, as
// [RequestID] does for a live request.
//
// Exported for the same reason as [ContextWithScopes]: a handler test
// that needs a request-scoped id without standing up the whole
// middleware chain, and any future composer of such a context. The
// production writer remains [RequestID] and nothing else — this does
// not reach the X-Request-Id response header, so a caller that uses it
// outside a test is creating an id no client will ever see.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDCtxKey{}, id)
}

type requestIDCtxKey struct{}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand never errors on supported platforms; if it
		// somehow does, a constant placeholder is safer than
		// panicking a request-handling goroutine.
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// DefaultMaxBodyBytes is the per-request body limit installed by
// MaxBodySize when no explicit value is given. 1 MiB is well above any
// typical JSON API payload; services with a route that legitimately
// needs more should install MaxBodySize per-route
// with a higher limit (the per-route handler runs before the route's
// handler reads the body, so its smaller cap takes precedence) or
// move that route off the global chain entirely.
const DefaultMaxBodyBytes int64 = 1 << 20

// MaxBodySize caps the request body and surfaces overflow as a typed
// 413 envelope (CodeRequestTooLarge), not a raw status. Two layers:
//
//   - Fast path: the announced Content-Length is over the limit, so
//     no body bytes are read. Common case for any honest client.
//   - Slow path: the body is chunked, or the Content-Length is wrong
//     or absent. Wrap c.Request.Body with http.MaxBytesReader so reads
//     past the limit fail downstream. Handlers binding via
//     c.ShouldBindJSON will surface the read failure as their usual
//     CodeInvalidRequest (400). 400 vs 413 is a quibble in that case
//     since the client is already misbehaving on transport, and the
//     important property — the body never grows past `limit` bytes
//     in memory — holds either way.
//
// CF's per-app memory quota is 128 MiB, so without this an
// authenticated caller can flatten a backend with a single 100 MiB POST.
// The Gin binder reads the body into memory; btpingo.Service.CallOnPremiseMutating
// also buffers the body for the CSRF retry. Both paths are therefore
// memory-bound by this cap.
//
// Services with a single legitimately larger route should install a
// per-route override with the appropriate limit:
//
//	r.POST("/large-import",
//	    btpingo.MaxBodySize(50<<20),  // 50 MiB just for this route
//	    importHandler)
//
// Per-route Use stacks before the handler; if the global Use also
// installs MaxBodySize, install the smaller of the two first (it
// rejects on the fast path and short-circuits the bigger one).
func MaxBodySize(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > limit {
			AbortError(c, http.StatusRequestEntityTooLarge, CodeRequestTooLarge,
				"request body exceeds size limit", nil)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

// RequireScope aborts the request with 403 forbidden unless the
// validated JWT's "scope" claim contains the exact scope string given.
//
// The check is exact — `User` matches `User`, not `user`, not `User.Admin`,
// not `Unauthorized-User`. Partial matching via strings.Contains /
// strings.HasPrefix / strings.HasSuffix is the classic bug here; keeping
// the check strict means no caller can accidentally widen access by
// relying on a looser match.
//
// **XSUAA qualified-scope gotcha.** Real XSUAA tokens emit scopes
// qualified with xsappname + tenant, e.g.
//
//	"myapp!t1234.Admin"
//
// not a bare `"Admin"`. Pass the qualified string you actually see in
// the token — the value of `XSUAACredentials.XSAppName` plus `!t` plus
// the tenant suffix plus `.` plus the scope name from
// `xs-security.json`. Concretely: decode one real token once and copy
// the exact shape out of its `scope` claim. Callers that pass a bare
// name will 403 every request — this is the single most common
// surprise when wiring a first scope-gated route.
//
// Install AFTER JWTValidator.Middleware() so "jwtClaims" is already in
// the context:
//
//	api := r.Group("/api")
//	api.Use(validator.Middleware())
//	api.GET("/admin", btpingo.RequireScope("myapp!t1234.Admin"), adminHandler)
//
// On failure, AbortError writes the typed CodeForbidden envelope. The
// underlying miss is NOT logged (err = nil) because 403 is a routine
// authz decision rather than a server-side error; callers that want the
// miss logged can wrap RequireScope and log themselves.
func RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := c.Get("jwtClaims")
		if !ok {
			// JWTValidator.Middleware missing from the chain — treat
			// as forbidden so a mis-wired router cannot expose a
			// scope-gated endpoint by accident.
			AbortError(c, http.StatusForbidden, CodeForbidden,
				"scope check requires authenticated user", nil)
			return
		}
		claims, ok := raw.(jwt.MapClaims)
		if !ok {
			AbortError(c, http.StatusForbidden, CodeForbidden,
				"scope check requires authenticated user", nil)
			return
		}
		scopes := extractScopes(claims)
		if !slices.Contains(scopes, scope) {
			AbortError(c, http.StatusForbidden, CodeForbidden,
				"missing required scope", nil)
			return
		}
		c.Next()
	}
}

// extractScopes reads the "scope" claim in either XSUAA shape (an array
// of strings) or the OAuth 2 bare-string shape (whitespace-separated).
// Both are valid in the wild; normalising at the read site keeps
// RequireScope strict without needing two near-identical code paths.
func extractScopes(claims jwt.MapClaims) []string {
	switch v := claims["scope"].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if str, ok := s.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case []string:
		return v
	case string:
		// strings.Fields splits on any Unicode whitespace and drops
		// empty entries, so double spaces / tabs / leading-trailing
		// whitespace all Just Work.
		return strings.Fields(v)
	}
	return nil
}
