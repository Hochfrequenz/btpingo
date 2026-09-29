package ginpingo

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
)

// RequestIDContextKey is the Gin context key under which the RequestID
// middleware stashes the request ID. AbortError reads it via
// c.Get(RequestIDContextKey) to populate the error envelope; handlers
// that want to annotate their slog lines with the request ID should do
// the same.
//
// This is a string because Gin's c.Set/c.Get map uses string keys.
// The context.Context propagation path uses a separately-defined
// typed key internal to btpingo — that's the canonical Go pattern for
// ctx.Value to avoid cross-package collisions (go vet / staticcheck
// flag string keys on context.WithValue).
const RequestIDContextKey = "request_id"

// RequestID reads an existing X-Request-Id header or generates a
// short hex token, stashes it in the Gin context under
// RequestIDContextKey, and echoes it back in the response. Installing
// this on the top-level router means every handler, every error
// envelope, and the access log share one correlation ID.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader(btpingo.RequestIDHeader)
		if rid == "" || !btpingo.ValidRequestID(rid) {
			rid = btpingo.NewRequestID()
		}
		c.Set(RequestIDContextKey, rid)
		c.Writer.Header().Set(btpingo.RequestIDHeader, rid)
		// Also propagate through the request context so handlers using
		// slog.InfoContext pick it up if they wire an slog handler that
		// reads the value (not every service does, but making the
		// value reachable from ctx means it is there when they do).
		ctx := btpingo.ContextWithRequestID(c.Request.Context(), rid)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
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
// 413 envelope (btpingo.CodeRequestTooLarge), not a raw status. Two
// layers:
//
//   - Fast path: the announced Content-Length is over the limit, so
//     no body bytes are read. Common case for any honest client.
//   - Slow path: the body is chunked, or the Content-Length is wrong
//     or absent. Wrap c.Request.Body with http.MaxBytesReader so reads
//     past the limit fail downstream. Handlers binding via
//     c.ShouldBindJSON will surface the read failure as their usual
//     btpingo.CodeInvalidRequest (400). 400 vs 413 is a quibble in that
//     case since the client is already misbehaving on transport, and
//     the important property — the body never grows past `limit` bytes
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
//	    ginpingo.MaxBodySize(50<<20),  // 50 MiB just for this route
//	    importHandler)
//
// Per-route Use stacks before the handler; if the global Use also
// installs MaxBodySize, install the smaller of the two first (it
// rejects on the fast path and short-circuits the bigger one).
func MaxBodySize(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > limit {
			AbortError(c, http.StatusRequestEntityTooLarge, btpingo.CodeRequestTooLarge,
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
// Install AFTER JWT(validator) so ClaimsContextKey is already in
// the context:
//
//	api := r.Group("/api")
//	api.Use(ginpingo.JWT(validator))
//	api.GET("/admin", ginpingo.RequireScope("myapp!t1234.Admin"), adminHandler)
//
// On failure, AbortError writes the typed btpingo.CodeForbidden
// envelope. The underlying miss is NOT logged (err = nil) because 403
// is a routine authz decision rather than a server-side error; callers
// that want the miss logged can wrap RequireScope and log themselves.
func RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := c.Get(ClaimsContextKey)
		if !ok {
			// JWT missing from the chain — treat as forbidden so a
			// mis-wired router cannot expose a scope-gated endpoint
			// by accident.
			AbortError(c, http.StatusForbidden, btpingo.CodeForbidden,
				"scope check requires authenticated user", nil)
			return
		}
		claims, ok := raw.(jwt.MapClaims)
		if !ok {
			AbortError(c, http.StatusForbidden, btpingo.CodeForbidden,
				"scope check requires authenticated user", nil)
			return
		}
		scopes := btpingo.ScopesFromClaims(claims)
		if !slices.Contains(scopes, scope) {
			AbortError(c, http.StatusForbidden, btpingo.CodeForbidden,
				"missing required scope", nil)
			return
		}
		c.Next()
	}
}
