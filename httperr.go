package btpingo

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
// RequestID is populated by [github.com/hochfrequenz/btpingo/ginpingo.AbortError]
// from the request ID stashed by
// [github.com/hochfrequenz/btpingo/ginpingo.RequestID] when that
// middleware is installed; omitted otherwise so the envelope stays
// compact.
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
