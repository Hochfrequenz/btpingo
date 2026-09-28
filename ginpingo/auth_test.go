package ginpingo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/ginpingo"
	"github.com/hochfrequenz/btpingo/internal/testkit"
)

func Test_JWT_Rejects_MissingBearer(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, _ := testkit.NewValidator(t, f, "GoApp")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.JWT(v))
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	then.AssertThat(t, w.Code, is.EqualTo(http.StatusUnauthorized))

	// Symmetry with Test_JWT_Rejects_Malformed: pin the envelope shape
	// on the no-bearer branch too.
	var env btpingo.ErrorEnvelope
	then.AssertThat(t, json.Unmarshal(w.Body.Bytes(), &env), is.Nil())
	then.AssertThat(t, env.Error.Code, is.EqualTo(btpingo.CodeUnauthorized))
	then.AssertThat(t, env.Error.Message, is.EqualTo("missing bearer token"))
}

func Test_JWT_Rejects_Malformed(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, _ := testkit.NewValidator(t, f, "GoApp")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.JWT(v))
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	then.AssertThat(t, w.Code, is.EqualTo(http.StatusUnauthorized))

	// Envelope shape for the "invalid token" branch. The raw jwt/keyfunc
	// error must NOT appear in the response body — only a stable message
	// behind the typed code.
	var env btpingo.ErrorEnvelope
	then.AssertThat(t, json.Unmarshal(w.Body.Bytes(), &env), is.Nil())
	then.AssertThat(t, env.Error.Code, is.EqualTo(btpingo.CodeUnauthorized))
	then.AssertThat(t, env.Error.Message, is.EqualTo("invalid or expired token"))
	// jwt/v5 library internals should never leak.
	then.AssertThat(t, strings.Contains(w.Body.String(), "token is malformed"),
		is.False())
}

func Test_JWT_AcceptsAndStashesToken(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, issuer := testkit.NewValidator(t, f, "GoApp")

	raw := f.Mint(t, jwt.MapClaims{
		"iss": issuer,
		"aud": "GoApp",
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "u",
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.JWT(v))
	r.GET("/x", func(c *gin.Context) {
		tokStr, _ := c.Request.Context().Value(btpingo.ForwardedUserTokenKey{}).(string)
		_, ok := c.Get(ginpingo.ClaimsContextKey)
		then.AssertThat(t, ok, is.True())
		then.AssertThat(t, tokStr, is.EqualTo(raw))
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
}

// Test_JWT_PutsScopesOnTheRequestContext pins the half of the stash a
// huma operation depends on. Claims land in the GIN context, which
// only a gin handler can read; a huma operation sees nothing but a
// context.Context, so a per-caller decision inside one — e.g. a
// reported "may read data" capability — is impossible without this.
// The scopes must be the token's, and a scope the token does not carry must not appear.
func Test_JWT_PutsScopesOnTheRequestContext(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, issuer := testkit.NewValidator(t, f, "GoApp")

	raw := f.Mint(t, jwt.MapClaims{
		"iss":   issuer,
		"aud":   "GoApp",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"sub":   "u",
		"scope": []string{"myapp!t1234.User", "myapp!t1234.ReadData"},
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.JWT(v))
	r.GET("/x", func(c *gin.Context) {
		ctx := c.Request.Context()
		then.AssertThat(t, btpingo.HasScope(ctx, "myapp!t1234.ReadData"), is.True())
		then.AssertThat(t, btpingo.HasScope(ctx, "myapp!t1234.Admin"), is.False())
		then.AssertThat(t, len(btpingo.ScopesFromContext(ctx)), is.EqualTo(2))
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
}
