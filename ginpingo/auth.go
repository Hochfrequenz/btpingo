package ginpingo

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hochfrequenz/btpingo"
)

// ClaimsContextKey is the Gin context key under which JWT stashes the
// validated token's parsed claims (a jwt.MapClaims). RequireScope reads
// claims from this key to make its authorization decision.
const ClaimsContextKey = "jwtClaims"

// JWT enforces a valid JWT on Authorization: Bearer, using v. The raw
// token is stashed in the request context under
// btpingo.ForwardedUserTokenKey{} so downstream authenticators
// (PrincipalPropagation) can reuse it; parsed claims land in the Gin
// context under ClaimsContextKey, and the token's scopes additionally
// land in the request context for handlers that never see a
// *gin.Context — see [btpingo.ScopesFromContext].
func JWT(v *btpingo.JWTValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			AbortError(c, http.StatusUnauthorized, btpingo.CodeUnauthorized,
				"missing bearer token", nil)
			return
		}
		raw := strings.TrimPrefix(h, "Bearer ")
		claims, err := v.Parse(raw)
		if err != nil {
			// The underlying jwt/keyfunc error can carry "kid not found",
			// "token expired at …", etc. Those are useful for operators
			// but not something we want on the client — log it, show a
			// stable message with the same code.
			AbortError(c, http.StatusUnauthorized, btpingo.CodeUnauthorized,
				"invalid or expired token", err)
			return
		}
		c.Set(ClaimsContextKey, claims)
		ctx := context.WithValue(c.Request.Context(), btpingo.ForwardedUserTokenKey{}, raw)
		// Scopes go into the REQUEST context as well as the Gin one.
		// RequireScope reads the Gin context and that stays as it is,
		// but a huma operation only ever sees a context.Context — the
		// humagin adapter hands it c.Request.Context() and nothing
		// else. Without this line a huma handler cannot make a
		// per-caller decision at all — e.g. reporting a capability
		// evaluated against the caller's token rather than only
		// against a deployment-wide switch.
		ctx = btpingo.ContextWithScopes(ctx, btpingo.ScopesFromClaims(claims))
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
