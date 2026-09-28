package ginpingo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/ginpingo"
)

func Test_RequestID_GeneratesWhenAbsent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID())
	r.GET("/x", func(c *gin.Context) {
		rid, _ := c.Get(ginpingo.RequestIDContextKey)
		c.String(http.StatusOK, rid.(string))
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
	rid := w.Header().Get(btpingo.RequestIDHeader)
	then.AssertThat(t, rid != "", is.True())
	then.AssertThat(t, len(rid), is.EqualTo(16))
	// Body echoed from c.Get must match the header — both sides of the
	// contract read from the same source.
	then.AssertThat(t, w.Body.String(), is.EqualTo(rid))
}

func Test_RequestID_PreservesInbound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID())
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(btpingo.RequestIDHeader, "external-rid-42")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Header().Get(btpingo.RequestIDHeader), is.EqualTo("external-rid-42"))
}

// Test_RequestID_RejectsOversizedInbound: nothing upstream of the app
// is guaranteed to validate X-Request-Id (an app may be reachable
// without an approuter in front of it), so an unbounded
// caller-supplied value must not reach the response header, the error
// envelope or every log line for the request untouched.
func Test_RequestID_RejectsOversizedInbound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID())
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	oversized := make([]byte, 65)
	for i := range oversized {
		oversized[i] = 'a'
	}

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(btpingo.RequestIDHeader, string(oversized))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	rid := w.Header().Get(btpingo.RequestIDHeader)
	then.AssertThat(t, rid, is.Not(is.EqualTo(string(oversized))).Reason(
		"an oversized caller-supplied id must not be echoed verbatim"))
	then.AssertThat(t, len(rid), is.EqualTo(16))
}

// Test_RequestID_AcceptsMaxLengthInbound pins the regex's boundary
// from the accepting side: Test_RequestID_RejectsOversizedInbound
// above only proves 65 bytes is rejected, which does not by itself
// show the pattern's stated {1,64} bound is where the acceptance edge
// actually sits.
func Test_RequestID_AcceptsMaxLengthInbound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID())
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	maxLength := make([]byte, 64)
	for i := range maxLength {
		maxLength[i] = 'a'
	}

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(btpingo.RequestIDHeader, string(maxLength))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Header().Get(btpingo.RequestIDHeader), is.EqualTo(string(maxLength)))
}

// Test_RequestID_RejectsDisallowedCharacters is the other half of the
// same guard: a value that fits the length bound but carries a
// character outside the allowed set (here, a newline — the shape that
// would otherwise let a caller inject an extra line into structured
// log output built by naive concatenation) must also be replaced
// rather than trusted.
func Test_RequestID_RejectsDisallowedCharacters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID())
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(btpingo.RequestIDHeader, "line1\nline2")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	rid := w.Header().Get(btpingo.RequestIDHeader)
	then.AssertThat(t, rid, is.Not(is.EqualTo("line1\nline2")))
	then.AssertThat(t, len(rid), is.EqualTo(16))
}

func Test_RequestID_PropagatesThroughContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID())
	r.GET("/x", func(c *gin.Context) {
		got := btpingo.RequestIDFromContext(c.Request.Context())
		c.String(http.StatusOK, got)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(btpingo.RequestIDHeader, "ctx-rid")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Body.String(), is.EqualTo("ctx-rid"))
}

func Test_RequestIDFromContext_NoMiddleware(t *testing.T) {
	// A bare context without the middleware yields "". Handlers that
	// want the ID unconditionally should either install the middleware
	// or tolerate the empty string.
	then.AssertThat(t, btpingo.RequestIDFromContext(context.Background()), is.EqualTo(""))
}

// Test_ContextWithRequestID_RoundTrips pins the exported setter that
// callers' handler tests (e.g. of a huma error envelope) use in place
// of the whole middleware chain.
//
// It must use the SAME private key RequestID writes — a setter that
// stored under a key of its own would round-trip through its own getter
// and be invisible to RequestIDFromContext, which is the only reader
// that matters. Asserting through RequestIDFromContext rather than
// through a second Value lookup is what makes that testable.
func Test_ContextWithRequestID_RoundTrips(t *testing.T) {
	ctx := btpingo.ContextWithRequestID(context.Background(), "abc123")
	then.AssertThat(t, btpingo.RequestIDFromContext(ctx), is.EqualTo("abc123"))

	// Overwriting is last-writer-wins, as context.WithValue is.
	then.AssertThat(t, btpingo.RequestIDFromContext(
		btpingo.ContextWithRequestID(ctx, "def456")), is.EqualTo("def456"))
}

// stubClaimsMiddleware simulates ginpingo.JWT for scope tests without
// standing up a JWKS / token pair. We only need ClaimsContextKey to be
// populated; RequireScope is tested end-to-end elsewhere.
func stubClaimsMiddleware(claims jwt.MapClaims) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ginpingo.ClaimsContextKey, claims)
		c.Next()
	}
}

func Test_RequireScope_AllowsWhenScopeArrayContains(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(stubClaimsMiddleware(jwt.MapClaims{
		"scope": []any{"User", "Admin"},
	}))
	r.GET("/admin", ginpingo.RequireScope("Admin"), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
	then.AssertThat(t, w.Body.String(), is.EqualTo("ok"))
}

func Test_RequireScope_AllowsWhenScopeStringContains(t *testing.T) {
	// OAuth-2 bare-string scope claim: "User Admin".
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(stubClaimsMiddleware(jwt.MapClaims{"scope": "User Admin"}))
	r.GET("/admin", ginpingo.RequireScope("Admin"), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
}

func Test_RequireScope_RejectsMissingScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(stubClaimsMiddleware(jwt.MapClaims{
		"scope": []any{"User"},
	}))
	r.GET("/admin", ginpingo.RequireScope("Admin"), func(c *gin.Context) {
		t.Fatal("handler should not run")
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusForbidden))
	var env btpingo.ErrorEnvelope
	then.AssertThat(t, json.Unmarshal(w.Body.Bytes(), &env), is.Nil())
	then.AssertThat(t, env.Error.Code, is.EqualTo(btpingo.CodeForbidden))
}

// Test_RequireScope_RejectsPartialMatch pins the strict-equality rule:
// "User" must not grant access to a scope called "UserAdmin". If the
// check ever regresses to strings.Contains, this test fails — exactly
// the kind of scope-expansion bug that goes unnoticed until it matters.
func Test_RequireScope_RejectsPartialMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(stubClaimsMiddleware(jwt.MapClaims{"scope": []any{"Unauthorized-User"}}))
	r.GET("/x", ginpingo.RequireScope("User"), func(c *gin.Context) {
		t.Fatal("handler should not run")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusForbidden))
}

// Test_RequireScope_RejectsPrefixMatch pins against the complementary
// regression: "Admin.Read" must not grant "Admin". If the check ever
// becomes strings.HasPrefix, this test fails. This kind of bug is
// insidious because lots of scope schemes use dotted hierarchy.
func Test_RequireScope_RejectsPrefixMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(stubClaimsMiddleware(jwt.MapClaims{"scope": []any{"Admin.Read"}}))
	r.GET("/x", ginpingo.RequireScope("Admin"), func(c *gin.Context) {
		t.Fatal("handler should not run")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusForbidden))
}

// Test_RequireScope_AllowsWhenScopeStringSliceContains covers the
// []string wire shape that ScopesFromClaims explicitly supports but
// none of the other tests exercise.
func Test_RequireScope_AllowsWhenScopeStringSliceContains(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(stubClaimsMiddleware(jwt.MapClaims{
		"scope": []string{"User", "Admin"},
	}))
	r.GET("/admin", ginpingo.RequireScope("Admin"), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
}

// Test_RequireScope_StringClaimWithDoubleSpaces pins strings.Fields
// behaviour on the whitespace-separated scope shape: double spaces,
// tabs, and leading/trailing whitespace must all resolve to the same
// set of scope tokens.
func Test_RequireScope_StringClaimWithDoubleSpaces(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Deliberately messy: leading space, double space between tokens, trailing tab.
	r.Use(stubClaimsMiddleware(jwt.MapClaims{"scope": "  User   Admin\t"}))
	r.GET("/admin", ginpingo.RequireScope("Admin"), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
}

func Test_RequireScope_RejectsWhenMiddlewareAbsent(t *testing.T) {
	// No stubClaimsMiddleware — claims are absent. RequireScope must
	// treat that as forbidden, not as "let through".
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", ginpingo.RequireScope("User"), func(c *gin.Context) {
		t.Fatal("handler should not run")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusForbidden))
}

// Test_MaxBodySize_RejectsOversizedContentLength pins the fast path:
// a POST whose Content-Length exceeds the limit is rejected with a
// typed CodeRequestTooLarge envelope before the body is read at all.
func Test_MaxBodySize_RejectsOversizedContentLength(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID(), ginpingo.MaxBodySize(1024)) // 1 KiB cap for the test
	bodyReadCount := 0
	r.POST("/x", func(c *gin.Context) {
		// Should never run — middleware aborts before us.
		_, _ = io.Copy(io.Discard, c.Request.Body)
		bodyReadCount++
		c.String(http.StatusOK, "ok")
	})

	// 2 KiB body, well over the 1 KiB cap. Use bytes.Repeat to keep the
	// test source small.
	body := bytes.Repeat([]byte("A"), 2048)
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusRequestEntityTooLarge))
	var env btpingo.ErrorEnvelope
	then.AssertThat(t, json.Unmarshal(w.Body.Bytes(), &env), is.Nil())
	then.AssertThat(t, env.Error.Code, is.EqualTo(btpingo.CodeRequestTooLarge))
	then.AssertThat(t, env.Error.RequestID != "", is.True())
	// Handler MUST NOT have run — the whole point of the fast path.
	then.AssertThat(t, bodyReadCount, is.EqualTo(0))
}

// Test_MaxBodySize_AllowsBodiesUnderLimit pins that bodies at or under
// the limit pass through to the handler unchanged.
func Test_MaxBodySize_AllowsBodiesUnderLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.MaxBodySize(1024))
	r.POST("/x", func(c *gin.Context) {
		raw, err := io.ReadAll(c.Request.Body)
		then.AssertThat(t, err, is.Nil())
		c.String(http.StatusOK, string(raw))
	})

	body := bytes.Repeat([]byte("B"), 1024) // exactly at the limit
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
	then.AssertThat(t, w.Body.Len(), is.EqualTo(1024))
}

// Test_MaxBodySize_CapsLyingContentLength pins the slow path: a client
// that sends Content-Length: 0 (or no header at all) but actually
// streams more than the limit hits the wrapped reader's MaxBytesError.
// The body never grows past `limit` bytes in memory — that's the
// invariant this middleware exists for.
func Test_MaxBodySize_CapsLyingContentLength(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.MaxBodySize(1024))
	var readErr error
	var readBytes int
	r.POST("/x", func(c *gin.Context) {
		var raw []byte
		raw, readErr = io.ReadAll(c.Request.Body)
		readBytes = len(raw)
		c.String(http.StatusOK, "")
	})

	body := bytes.Repeat([]byte("C"), 4096) // 4 KiB actual body
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
	req.ContentLength = -1 // simulate chunked / unknown length
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// The body read must error and never have read past the cap.
	then.AssertThat(t, readErr, is.Not(is.Nil()))
	then.AssertThat(t, readBytes <= 1024, is.True())
}

// Test_RequestID_PopulatesErrorEnvelope ties the two middlewares
// together: when AbortError fires in a later handler, the envelope
// carries the ID set by RequestID.
func Test_RequestID_PopulatesErrorEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID())
	r.GET("/boom", func(c *gin.Context) {
		ginpingo.AbortError(c, http.StatusBadGateway, btpingo.CodeUpstreamUnreachable,
			"on-premise call failed", nil)
	})

	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	req.Header.Set(btpingo.RequestIDHeader, "envelope-rid")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var env btpingo.ErrorEnvelope
	then.AssertThat(t, json.Unmarshal(w.Body.Bytes(), &env), is.Nil())
	then.AssertThat(t, env.Error.RequestID, is.EqualTo("envelope-rid"))
}
