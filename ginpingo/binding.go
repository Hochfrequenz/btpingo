package ginpingo

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hochfrequenz/btpingo"
)

type bindOptions struct {
	maxBytes              int64
	disallowUnknownFields bool
}

// BindOption configures BindStrictJSON.
type BindOption func(*bindOptions)

// WithMaxBytes sets the per-call body limit. The default is DefaultMaxBodyBytes.
// Non-positive limits allow no body bytes.
func WithMaxBytes(n int64) BindOption {
	return func(o *bindOptions) { o.maxBytes = n }
}

// WithDisallowUnknownFields rejects JSON object fields not present in dst.
func WithDisallowUnknownFields() BindOption {
	return func(o *bindOptions) { o.disallowUnknownFields = true }
}

// BindStrictJSON decodes exactly one JSON value from the request body into dst.
// On failure it writes the error envelope via AbortError and returns false.
// Only JSON whitespace may follow the value. Binding-tag validation is not run.
// An existing MaxBodySize limit still applies even if WithMaxBytes is larger.
func BindStrictJSON(c *gin.Context, dst any, opts ...BindOption) bool {
	o := bindOptions{maxBytes: DefaultMaxBodyBytes}
	for _, opt := range opts {
		opt(&o)
	}

	body := c.Request.Body
	if body == nil {
		body = http.NoBody
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, body, o.maxBytes)
	// Read the entire bounded body first so decoder failures cannot mask overflow.
	data, err := io.ReadAll(c.Request.Body)
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(data))
		if o.disallowUnknownFields {
			decoder.DisallowUnknownFields()
		}
		if err = decoder.Decode(dst); err == nil {
			var extra json.RawMessage
			err = decoder.Decode(&extra)
			if errors.Is(err, io.EOF) {
				return true
			}
			if err == nil {
				err = errors.New("request body contains multiple JSON values")
			}
		}
	}

	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		AbortError(c, http.StatusRequestEntityTooLarge, btpingo.CodeRequestTooLarge,
			"request body exceeds size limit", err)
	} else {
		AbortError(c, http.StatusBadRequest, btpingo.CodeInvalidRequest,
			"request body must contain a single valid JSON value", err)
	}
	return false
}
