// Package ginpingo provides Gin adapters for btpingo: middleware and
// handlers that wrap the framework-neutral core in
// github.com/hochfrequenz/btpingo with Gin's *gin.Context. Import this
// package only from a Gin-based service; huma or other non-Gin
// services use the core package's context helpers directly
// ([btpingo.ScopesFromContext], [btpingo.HasScope],
// [btpingo.RequestIDFromContext]) and never need this one.
//
// # API surface
//
//   - [JWT]              — Gin middleware enforcing a valid JWT on Authorization: Bearer
//   - [ClaimsContextKey] — the Gin context key JWT stashes claims under, read by RequireScope
//   - [RequestID], [RequestIDContextKey] — request-ID middleware and its Gin context key
//   - [MaxBodySize], [DefaultMaxBodyBytes] — per-request body size cap
//   - [RequireScope]     — aborts with 403 unless the validated JWT carries a scope
//   - [AbortError]       — the single blessed writer for error responses
//   - [ProxyHandler]     — Gin pass-through handler for a generic proxy route
package ginpingo
