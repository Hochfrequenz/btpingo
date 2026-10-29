package grpcpingo

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
)

// TokenParser validates a raw bearer token and returns its claims.
// *btpingo.JWTValidator implements it.
type TokenParser interface {
	Parse(raw string) (jwt.MapClaims, error)
}

// AuthOption configures [Auth].
type AuthOption func(*authConfig)

type authConfig struct {
	fromClaims func(context.Context, jwt.MapClaims) context.Context
}

// WithContextFromClaims adds a hook that derives more request-context values
// from the validated claims, for example a caller id for the handlers. It runs
// only for a call that passed the token and scope checks, after the token and
// scopes are in the context, and must return a context derived from ctx.
func WithContextFromClaims(f func(context.Context, jwt.MapClaims) context.Context) AuthOption {
	return func(c *authConfig) { c.fromClaims = f }
}

// authInfo is what the authn AuthFunc hands to the wrapped handler through authn.SetInfo.
type authInfo struct {
	raw    string
	claims jwt.MapClaims
}

// Auth is the connect counterpart of ginpingo.JWT plus ginpingo.RequireScope.
// It requires "Authorization: Bearer <token>", validates the token with v and
// requires scope (a qualified scope such as "myapp!t1.User") in it. For an
// accepted call the request context carries what ginpingo.JWT puts there: the
// raw token under [btpingo.ForwardedUserTokenKey] and the token's scopes (see
// [btpingo.ScopesFromContext], [btpingo.HasScope]), plus whatever
// [WithContextFromClaims] adds.
//
// A rejected call is answered in the protocol of the request (gRPC, gRPC-Web
// or Connect; on a streaming call the status arrives on the stream) with the
// code and ErrorInfo of m: unauthorized for a missing or invalid token,
// forbidden for a missing scope. Like ginpingo.AbortError, only an invalid
// token is logged (once, at ERROR, with the parse error, which never reaches
// the client); a missing token and a missing scope are routine and stay
// silent.
//
// Auth is built on connectrpc.com/authn. It panics when scope is empty, so a
// wiring mistake cannot open the service to every valid token.
//
// Access logs in front of a gRPC service show HTTP 200 for a rejected call:
// the gRPC status travels in the trailers, not in the HTTP status.
func Auth(v TokenParser, scope string, m Mapper, opts ...AuthOption) func(http.Handler) http.Handler {
	if scope == "" {
		panic("grpcpingo: Auth needs a non-empty scope")
	}
	var cfg authConfig
	for _, o := range opts {
		o(&cfg)
	}
	mw := authn.NewMiddleware(func(ctx context.Context, req *http.Request) (any, error) {
		raw, ok := authn.BearerToken(req)
		if !ok || raw == "" {
			return nil, m.Error(btpingo.CodeUnauthorized, "missing bearer token")
		}
		claims, err := v.Parse(raw)
		if err != nil {
			// The parse error can name key ids and the like: log only.
			slog.ErrorContext(ctx, "grpc auth error",
				"code", string(btpingo.CodeUnauthorized),
				"grpc_code", connect.CodeUnauthenticated.String(),
				"request_id", btpingo.RequestIDFromContext(ctx),
				"err", err,
			)
			return nil, m.Error(btpingo.CodeUnauthorized, "invalid or expired token")
		}
		scoped := btpingo.ContextWithScopes(ctx, btpingo.ScopesFromClaims(claims))
		if !btpingo.HasScope(scoped, scope) {
			return nil, m.Error(btpingo.CodeForbidden, "missing required scope")
		}
		return authInfo{raw: raw, claims: claims}, nil
	})
	return func(next http.Handler) http.Handler {
		return mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, _ := authn.GetInfo(r.Context()).(authInfo)
			ctx := context.WithValue(r.Context(), btpingo.ForwardedUserTokenKey{}, info.raw)
			ctx = btpingo.ContextWithScopes(ctx, btpingo.ScopesFromClaims(info.claims))
			if cfg.fromClaims != nil {
				ctx = cfg.fromClaims(ctx, info.claims)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	}
}
