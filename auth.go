package btpingo

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// JWTValidator validates tokens minted by this app's XSUAA tenant. Construct
// once at startup; safe for concurrent use. The underlying keyfunc keeps the
// JWKS fresh on a background refresh loop.
type JWTValidator struct {
	xsuaa   *XSUAACredentials
	keyfunc jwt.Keyfunc
	parser  *jwt.Parser
}

// NewJWTValidator fetches the JWKS at xsuaa.JWKSURL() and returns a ready
// validator. It verifies: RS256 signature (keys pinned to xsuaa.JWKSURL()),
// audience = xsuaa.ClientID, standard exp/nbf/iat with TokenRefreshLeeway.
//
// The issuer claim is intentionally not checked. XSUAA emits an internal
// "http://<zone>.localhost:8080/uaa/oauth/token" iss that cannot be
// derived from VCAP_SERVICES without hardcoding a SAP implementation
// detail. Security is preserved by deriving the JWKS URL from this app's
// own XSUAA binding (xsuaa.URL + "/token_keys"), so the keyset only ever
// contains our tenant's signing keys; a token minted by a different
// tenant fails signature verification. Callers must keep that
// invariant — do not let the JWKS URL come from anywhere but the bound
// XSUAACredentials, or the iss-drop argument no longer holds.
func NewJWTValidator(ctx context.Context, xsuaa *XSUAACredentials) (*JWTValidator, error) {
	if xsuaa == nil {
		return nil, errors.New("xsuaa credentials required")
	}
	if xsuaa.URL == "" || xsuaa.ClientID == "" {
		return nil, errors.New("xsuaa credentials missing url or clientid")
	}

	kf, err := keyfunc.NewDefaultCtx(ctx, []string{xsuaa.JWKSURL()})
	if err != nil {
		return nil, fmt.Errorf("fetch jwks from %s: %w", xsuaa.JWKSURL(), err)
	}

	parser := jwt.NewParser(
		// RS256 is the only algorithm XSUAA signs with. Enforcing it
		// explicitly blocks the "alg: none" and "HS256 with the public key
		// as secret" classic confusion attacks.
		jwt.WithValidMethods([]string{"RS256"}),
		// Real XSUAA tokens carry aud entries like "sb-<xsappname>!t<tenant>"
		// (the clientid form), not the bare xsappname. Comparing against
		// ClientID matches what XSUAA actually emits.
		jwt.WithAudience(xsuaa.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(TokenRefreshLeeway),
		// jwt/v5 only validates iat when explicitly asked to; without
		// this, a token claiming to have been issued in the future
		// would parse as valid despite the doc comment above promising
		// iat is checked.
		jwt.WithIssuedAt(),
	)

	return &JWTValidator{xsuaa: xsuaa, keyfunc: kf.Keyfunc, parser: parser}, nil
}

func (v *JWTValidator) Parse(raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	if _, err := v.parser.ParseWithClaims(raw, claims, v.keyfunc); err != nil {
		return nil, err
	}
	return claims, nil
}

// ScopesFromClaims reads the "scope" claim in either XSUAA shape (an
// array of strings) or the OAuth 2 bare-string shape
// (whitespace-separated). Both are valid in the wild; normalising at
// the read site keeps a strict, exact scope check (e.g.
// ginpingo.RequireScope) from needing two near-identical code paths.
//
// Exported for the gin adapters (ginpingo.JWT populates
// [ContextWithScopes] with this, and ginpingo.RequireScope reads the
// claims by the same rule) and for any other framework adapter that
// needs the same normalisation.
func ScopesFromClaims(claims jwt.MapClaims) []string {
	switch v := claims["scope"].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if str, ok := s.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case []string:
		return v
	case string:
		// strings.Fields splits on any Unicode whitespace and drops
		// empty entries, so double spaces / tabs / leading-trailing
		// whitespace all Just Work.
		return strings.Fields(v)
	}
	return nil
}

// scopesCtxKey is the private context key the validated token's scopes
// are stashed under. Unexported and a struct type, so nothing outside
// this package can collide with it or forge an entry — the only writer
// is ginpingo.JWT, after the signature has been verified.
type scopesCtxKey struct{}

// ContextWithScopes returns ctx carrying the given scopes.
//
// [github.com/hochfrequenz/btpingo/ginpingo.JWT] is the only production
// caller, and it calls this only after the signature, audience and
// expiry have been verified — so a scope in a request context is
// always one XSUAA actually issued. It is exported for the other two
// legitimate composers of such a context: a handler test that needs a
// caller with a scope without minting a JWT, and any future middleware
// that authenticates by some other means. It is not an authorization
// decision; [HasScope] is.
func ContextWithScopes(ctx context.Context, scopes []string) context.Context {
	return context.WithValue(ctx, scopesCtxKey{}, scopes)
}

// ScopesFromContext returns the scopes of the validated token on this
// request, or nil when the request did not pass through
// [github.com/hochfrequenz/btpingo/ginpingo.JWT].
//
// Fail-closed by construction: an unauthenticated request, or a
// mis-wired router that skipped the validator, yields nil and therefore
// carries no scope. Callers must treat nil as "no scope", never as
// "check skipped".
func ScopesFromContext(ctx context.Context) []string {
	scopes, _ := ctx.Value(scopesCtxKey{}).([]string)
	// Cloned: the stored slice is what every later HasScope on this
	// request reads, and handing out the live one lets any caller sort,
	// truncate or overwrite the caller's own authorizations for the rest
	// of the request. One small allocation against a silent authz bug.
	return slices.Clone(scopes)
}

// HasScope reports whether the validated token on this request carries
// the given qualified scope (e.g. "myapp!t1234.ReadData").
//
// This is the huma-side counterpart of
// [github.com/hochfrequenz/btpingo/ginpingo.RequireScope], which is gin
// middleware and can only abort. A huma handler that must REPORT a
// capability rather than enforce it (e.g. a "may read data" flag in a
// response) needs to ask the question without rejecting the request,
// which is what this is for.
func HasScope(ctx context.Context, scope string) bool {
	return slices.Contains(ScopesFromContext(ctx), scope)
}
