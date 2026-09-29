package ginpingo

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	"github.com/hochfrequenz/btpingo"
)

// AbortError is the only blessed way to write an error response with
// this package. It constructs the envelope, logs the underlying Go
// error server-side (never exposed to the client), and aborts the
// handler chain. Handlers that hand-construct btpingo.ErrorEnvelope
// values bypass the logging side and break the contract the tests pin
// — don't do it unless you're deliberately extending the helper.
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
func AbortError(c *gin.Context, status int, code btpingo.ErrorCode, userMsg string, err error) {
	rid, _ := c.Get(RequestIDContextKey)
	ridStr, _ := rid.(string)
	if err != nil {
		slog.ErrorContext(c.Request.Context(), "api error",
			"code", string(code),
			"status", status,
			"request_id", ridStr,
			"err", err,
		)
	}
	c.AbortWithStatusJSON(status, btpingo.ErrorEnvelope{
		Error: btpingo.ErrorDetail{Code: code, Message: userMsg, RequestID: ridStr},
	})
}
