package ginpingo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
	"github.com/gin-gonic/gin"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/ginpingo"
)

func Test_BindStrictJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name       string
		body       string
		opts       []ginpingo.BindOption
		middleware gin.HandlerFunc
		status     int
		wantName   string
	}{
		{name: "valid", body: `{"name":"Ada"}`, status: http.StatusOK, wantName: "Ada"},
		{name: "whitespace", body: " \n{\"name\":\"Ada\"}\t\r\n ", status: http.StatusOK, wantName: "Ada"},
		{name: "empty", status: http.StatusBadRequest},
		{name: "only whitespace", body: " \t\r\n", status: http.StatusBadRequest},
		{name: "trailing garbage", body: `{"name":"Ada"} secret-decoder-detail`, status: http.StatusBadRequest},
		{name: "concatenated values", body: `{"name":"Ada"}{"name":"Bob"}`, status: http.StatusBadRequest},
		{name: "trailing null", body: `{"name":"Ada"} null`, status: http.StatusBadRequest},
		{name: "trailing malformed value", body: `{"name":"Ada"} {`, status: http.StatusBadRequest},
		{name: "malformed", body: `{"name":`, status: http.StatusBadRequest},
		{name: "invalid syntax", body: `{"name":secret-decoder-detail}`, status: http.StatusBadRequest},
		{name: "wrong field type", body: `{"name":42}`, status: http.StatusBadRequest},
		{name: "wrong top-level type", body: `[]`, status: http.StatusBadRequest},
		{name: "unknown allowed", body: `{"name":"Ada","secret-decoder-detail":1}`, status: http.StatusOK, wantName: "Ada"},
		{name: "unknown rejected", body: `{"name":"Ada","secret-decoder-detail":1}`,
			opts: []ginpingo.BindOption{ginpingo.WithDisallowUnknownFields()}, status: http.StatusBadRequest},
		{name: "known field strict", body: `{"name":"Ada"}`,
			opts: []ginpingo.BindOption{ginpingo.WithDisallowUnknownFields()}, status: http.StatusOK, wantName: "Ada"},
		{name: "over limit", body: `{"name":"Ada"}`,
			opts: []ginpingo.BindOption{ginpingo.WithMaxBytes(13)}, status: http.StatusRequestEntityTooLarge},
		{name: "exact limit", body: `{"name":"Ada"}`,
			opts: []ginpingo.BindOption{ginpingo.WithMaxBytes(14)}, status: http.StatusOK, wantName: "Ada"},
		{name: "overflow in trailing whitespace", body: `{"name":"Ada"} `,
			opts: []ginpingo.BindOption{ginpingo.WithMaxBytes(14)}, status: http.StatusRequestEntityTooLarge},
		{name: "overflow in second value", body: `{"name":"Ada"}{}`,
			opts: []ginpingo.BindOption{ginpingo.WithMaxBytes(15)}, status: http.StatusRequestEntityTooLarge},
		{name: "overflow with invalid syntax", body: `not JSON and over limit`,
			opts: []ginpingo.BindOption{ginpingo.WithMaxBytes(5)}, status: http.StatusRequestEntityTooLarge},
		{name: "zero limit", body: `{}`,
			opts: []ginpingo.BindOption{ginpingo.WithMaxBytes(0)}, status: http.StatusRequestEntityTooLarge},
		{name: "negative limit", body: `{}`,
			opts: []ginpingo.BindOption{ginpingo.WithMaxBytes(-1)}, status: http.StatusRequestEntityTooLarge},
		{name: "default limit", body: `{"name":"Ada"}` + strings.Repeat(" ", int(ginpingo.DefaultMaxBodyBytes)),
			status: http.StatusRequestEntityTooLarge},
		{name: "larger explicit limit", body: `{"name":"Ada"}` + strings.Repeat(" ", int(ginpingo.DefaultMaxBodyBytes)),
			opts:   []ginpingo.BindOption{ginpingo.WithMaxBytes(ginpingo.DefaultMaxBodyBytes + 14)},
			status: http.StatusOK, wantName: "Ada"},
		{name: "middleware tighter than binder", body: `{"name":"Ada"}`,
			middleware: ginpingo.MaxBodySize(13), status: http.StatusRequestEntityTooLarge},
		{name: "binder tighter than middleware", body: `{"name":"Ada"}`,
			middleware: ginpingo.MaxBodySize(100), opts: []ginpingo.BindOption{ginpingo.WithMaxBytes(13)},
			status: http.StatusRequestEntityTooLarge},
		{name: "binding validation deferred", body: `{}`, status: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(ginpingo.RequestID())
			if tt.middleware != nil {
				r.Use(tt.middleware)
			}
			var dst struct {
				Name string `json:"name" binding:"required"`
			}
			var bound bool
			r.POST("/", func(c *gin.Context) {
				bound = ginpingo.BindStrictJSON(c, &dst, tt.opts...)
				then.AssertThat(t, c.IsAborted(), is.EqualTo(!bound))
				if !bound {
					return
				}
				c.Status(http.StatusOK)
			}, func(c *gin.Context) {
				if !bound {
					t.Fatal("handler chain must abort on binding failure")
				}
			})

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.ContentLength = -1 // Exercise the read limit, not a Content-Length fast path.
			req.Header.Set(btpingo.RequestIDHeader, "bind-rid")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			then.AssertThat(t, w.Code, is.EqualTo(tt.status))
			then.AssertThat(t, bound, is.EqualTo(tt.status == http.StatusOK))
			if bound {
				then.AssertThat(t, dst.Name, is.EqualTo(tt.wantName))
				then.AssertThat(t, w.Body.Len(), is.EqualTo(0))
				return
			}
			var env btpingo.ErrorEnvelope
			then.AssertThat(t, json.Unmarshal(w.Body.Bytes(), &env), is.Nil())
			then.AssertThat(t, env.Error.RequestID, is.EqualTo("bind-rid"))
			if tt.status == http.StatusRequestEntityTooLarge {
				then.AssertThat(t, env.Error.Code, is.EqualTo(btpingo.CodeRequestTooLarge))
				then.AssertThat(t, env.Error.Message, is.EqualTo("request body exceeds size limit"))
			} else {
				then.AssertThat(t, env.Error.Code, is.EqualTo(btpingo.CodeInvalidRequest))
				then.AssertThat(t, env.Error.Message, is.EqualTo("request body must contain a single valid JSON value"))
			}
			for _, internal := range []string{"secret-decoder-detail", "unexpected EOF", "invalid character",
				"cannot unmarshal", "unknown field", "json:", "http: request body too large"} {
				then.AssertThat(t, strings.Contains(w.Body.String(), internal), is.False())
			}
		})
	}
}
