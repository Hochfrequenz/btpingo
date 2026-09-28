package btpingo

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

// ErrorCode is the typed code field on the API error envelope. The
// canonical set below covers the errors this package's own middleware
// and handlers produce; callers may declare their own codes as needed,
// but should keep the shape — clients are expected to switch on `code`, not on
// the human-readable `message`.
type ErrorCode string

const (
	CodeInvalidRequest      ErrorCode = "invalid_request"
	CodeUnauthorized        ErrorCode = "unauthorized"
	CodeForbidden           ErrorCode = "forbidden"
	CodeNotFound            ErrorCode = "not_found"
	CodeMethodNotAllowed    ErrorCode = "method_not_allowed"
	CodeRequestTooLarge     ErrorCode = "request_too_large"
	CodeUpstreamUnreachable ErrorCode = "upstream_unreachable"
	CodeInternal            ErrorCode = "internal"
)

// ErrorEnvelope is the shape every error response takes. Keeping all
// errors under a fixed key means clients can disambiguate success vs.
// failure by the presence of `error` without inspecting the HTTP status
// alone, and it leaves room to grow the envelope with metadata later.
type ErrorEnvelope struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail is the structured payload the client actually reads.
// RequestID is populated from the Gin context key "request_id" when the
// RequestID middleware is installed; omitted otherwise so the envelope
// stays compact.
//
// The `doc`/`example` struct tags are read by huma when it generates the
// published OpenAPI document's error schema — a huma API that marshals
// this very struct gets a documented error shape and an emitted one
// that are one definition rather than two that can drift. They are
// inert for the gin surface.
type ErrorDetail struct {
	Code      ErrorCode `json:"code" doc:"Stable, machine-readable error code. Clients switch on this, never on the message." example:"invalid_request"`
	Message   string    `json:"message" doc:"Human-readable explanation, safe to show a user. Names the field, the value and the constraint where those apply." example:"limit: must be at most 1000, got 5000"`
	RequestID string    `json:"request_id,omitempty" doc:"Correlation id for this request. Identical to the X-Request-Id response header; quote it in a support request." example:"7f3c1a9b2e4d5068"`
}

// AbortError is the only blessed way to write an error response with
// this package. It constructs the envelope, logs the underlying Go
// error server-side (never exposed to the client), and aborts the
// handler chain. Handlers that hand-construct ErrorEnvelope values
// bypass the logging side and break the contract the tests pin —
// don't do it unless you're deliberately extending the helper.
//
// Split of concerns:
//   - `userMsg` is what the client sees — always safe, always stable.
//     Hard-code it, don't pass err.Error() here. A leaking stack or
//     library-specific sentence in the response body would be the kind
//     of bug this helper exists to prevent.
//   - `err` is what the operator needs for triage — goes to slog with
//     the status, code, and request ID so a grep by request_id brings
//     back the full context without the client ever seeing it.
//
// Call sites that intentionally want to expose detail to the client
// (e.g. struct-tag validation errors from go-playground/validator,
// which are already safe to show) can set `userMsg` from err.Error()
// themselves — that is an explicit decision, not a default.
func AbortError(c *gin.Context, status int, code ErrorCode, userMsg string, err error) {
	rid, _ := c.Get("request_id")
	ridStr, _ := rid.(string)
	if err != nil {
		slog.ErrorContext(c.Request.Context(), "api error",
			"code", string(code),
			"status", status,
			"request_id", ridStr,
			"err", err,
		)
	}
	c.AbortWithStatusJSON(status, ErrorEnvelope{
		Error: ErrorDetail{Code: code, Message: userMsg, RequestID: ridStr},
	})
}
