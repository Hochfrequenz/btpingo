package btpingotest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
)

const (
	// TokenKeysPath is where the mock serves its JWKS.
	TokenKeysPath = "/token_keys"
	// TokenPath is where the mock serves the client_credentials grant.
	TokenPath = "/oauth/token"

	// DefaultTokenLifetime is the lifetime of the tokens the mock issues
	// unless XSUAAConfig.TokenLifetime says otherwise (XSUAA's default for
	// access tokens is 12 h).
	DefaultTokenLifetime = 12 * time.Hour

	keyID = "mock-key-1"

	defaultZoneID    = "mock-zone"
	defaultSubdomain = "mock"
)

// XSUAAClient is a caller the mock XSUAA knows: a client ID with its
// secret and the scopes its tokens carry (the granted scopes, qualified
// as in a real token, e.g. "myapp!t1.User").
type XSUAAClient struct {
	ClientID string
	Secret   string
	Scopes   []string
}

// XSUAAConfig configures NewXSUAA.
type XSUAAConfig struct {
	// XSAppName is the application's xsappname, e.g. "myapp!t1".
	XSAppName string
	// AppClientID is the application's own client ID (what a real
	// service key calls clientid, "sb-<xsappname>"). Every token carries
	// it in "aud", which is what btpingo.JWTValidator checks.
	AppClientID string
	// Clients are the callers that may fetch tokens. If the application's
	// own client (AppClientID) is not among them, NewXSUAA adds it with no
	// scopes and a generated secret, so Credentials is always usable at the
	// token endpoint.
	Clients []XSUAAClient
	// ZoneID is the identity zone ("zid" claim). Default "mock-zone".
	ZoneID string
	// Subdomain is the tenant subdomain, used in "iss" and "ext_attr.zdn".
	// Default "mock".
	Subdomain string
	// TokenLifetime is the lifetime of issued tokens. Default
	// DefaultTokenLifetime (12 h).
	TokenLifetime time.Duration
	// Now is the clock for iat/exp. Default time.Now.
	Now func() time.Time
}

// XSUAA is a mock of the XSUAA endpoints a btpingo-based service uses:
// the JWKS (GET /token_keys) and the client_credentials grant
// (POST /oauth/token). It is an http.Handler that can be mounted on any
// mux; it runs no server of its own. It is meant for tests and local
// mocks only and must never be wired into a production binary.
//
// Token shape, as measured against a real XSUAA for a client_credentials
// token: "aud" holds the caller's own client ID plus the namespaces of the
// granted scopes ("myapp!t1" for "myapp!t1.User", "openid" for "openid"),
// not the application's client ID unless the caller is that client.
//
// Known consequence with btpingo's current validator: JWTValidator
// requires the application's client ID in "aud". A token of a foreign
// client that was granted the application's scope (grant-as-authority-to-apps)
// carries aud [foreign-id, "<xsappname>"] and is therefore rejected with
// 401; only tokens of the application's own client pass. This is a
// suspected production limitation, pinned by a test, not yet verified
// against a real XSUAA.
type XSUAA struct {
	cfg XSUAAConfig
	key *rsa.PrivateKey
	jwk []byte
}

var _ http.Handler = (*XSUAA)(nil)

// NewXSUAA generates a fresh RSA key and returns the mock.
func NewXSUAA(cfg XSUAAConfig) (*XSUAA, error) {
	if cfg.XSAppName == "" || cfg.AppClientID == "" {
		return nil, errors.New("btpingotest: XSAppName and AppClientID are required")
	}
	seen := map[string]bool{}
	for _, c := range cfg.Clients {
		if c.ClientID == "" || c.Secret == "" {
			return nil, errors.New("btpingotest: every client needs a ClientID and a Secret")
		}
		if seen[c.ClientID] {
			return nil, fmt.Errorf("btpingotest: duplicate client %q", c.ClientID)
		}
		seen[c.ClientID] = true
	}
	if cfg.ZoneID == "" {
		cfg.ZoneID = defaultZoneID
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Subdomain == "" {
		cfg.Subdomain = defaultSubdomain
	}
	if cfg.TokenLifetime <= 0 {
		cfg.TokenLifetime = DefaultTokenLifetime
	}
	cfg.Clients = slices.Clone(cfg.Clients)
	if !seen[cfg.AppClientID] {
		var sec [16]byte
		_, _ = rand.Read(sec[:])
		cfg.Clients = append(cfg.Clients, XSUAAClient{ClientID: cfg.AppClientID, Secret: hex.EncodeToString(sec[:])})
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("btpingotest: generate rsa key: %w", err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": keyID,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		return nil, err
	}
	return &XSUAA{cfg: cfg, key: key, jwk: jwks}, nil
}

// Credentials returns the binding of the application as a service key
// would show it, pointed at baseURL (the URL the mock is reachable
// under, without trailing path). It passes Validate, and
// btpingo.NewJWTValidator fetches the JWKS from baseURL + "/token_keys".
// ClientID is the application client ID; ClientSecret is that client's
// secret (generated if the client was not configured).
func (x *XSUAA) Credentials(baseURL string) *btpingo.XSUAACredentials {
	var secret string
	for _, c := range x.cfg.Clients {
		if c.ClientID == x.cfg.AppClientID {
			secret = c.Secret
		}
	}
	return &btpingo.XSUAACredentials{
		URL:          strings.TrimRight(baseURL, "/"),
		ClientID:     x.cfg.AppClientID,
		ClientSecret: secret,
		XSAppName:    x.cfg.XSAppName,
		UAADomain:    "localhost",
		Identityzone: x.cfg.ZoneID,
	}
}

// MintToken returns a signed token for a configured client, as the
// client_credentials grant would, without HTTP. Without scopes the token
// carries all of the client's scopes; with scopes it is narrowed to them
// like the "scope" form parameter (an ungranted scope is an error).
func (x *XSUAA) MintToken(clientID string, scopes ...string) (string, error) {
	c, ok := x.client(clientID)
	if !ok {
		return "", fmt.Errorf("btpingotest: unknown client %q", clientID)
	}
	granted, err := narrow(c.Scopes, scopes)
	if err != nil {
		return "", err
	}
	return x.Sign(x.claims(c, granted))
}

// narrow returns the intersection semantics of UAA: requested scopes must
// all be granted; none requested means all granted.
func narrow(granted, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return slices.Clone(granted), nil
	}
	out := make([]string, 0, len(requested))
	for _, r := range requested {
		if !slices.Contains(granted, r) {
			return nil, fmt.Errorf("btpingotest: scope %q is not granted to the client", r)
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// Sign signs arbitrary claims with the mock's key (RS256, header kid), for
// tests of rejected tokens (expired, foreign audience, ...). The claims
// type comes from github.com/golang-jwt/jwt/v5, so this method exposes
// that module in btpingotest's API.
func (x *XSUAA) Sign(claims jwt.Claims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = keyID
	return tok.SignedString(x.key)
}

// ServeHTTP serves TokenKeysPath and TokenPath; mount it on "/" of a mux
// or register the two paths. Any other path answers 404.
func (x *XSUAA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case TokenKeysPath:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(x.jwk)
	case TokenPath:
		x.serveToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Register mounts the mock's two routes on mux.
func (x *XSUAA) Register(mux *http.ServeMux) {
	mux.Handle(TokenKeysPath, x)
	mux.Handle(TokenPath, x)
}

func (x *XSUAA) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Request method '"+r.Method+"' is not supported")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Malformed form body")
		return
	}
	// Credentials: HTTP Basic wins, form fields are the fallback.
	id, secret, ok := r.BasicAuth()
	if ok && strings.EqualFold(r.Header.Get("X-CF-ENCODED-CREDENTIALS"), "true") {
		// Like UAA: only with this header are Basic credentials
		// percent-decoded; otherwise they are compared raw.
		var e1, e2 error
		id, e1 = url.QueryUnescape(id)
		secret, e2 = url.QueryUnescape(secret)
		if e1 != nil || e2 != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Malformed encoded credentials")
			return
		}
	}
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	c, known := x.client(id)
	// Always compare, so timing does not tell known from unknown IDs.
	secretOK := subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) == 1
	if !known || !secretOK || secret == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="UAA/client"`)
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized", "Bad credentials")
		return
	}
	if g := r.PostForm.Get("grant_type"); g != "client_credentials" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type: "+g)
		return
	}
	granted, err := narrow(c.Scopes, strings.Fields(r.PostForm.Get("scope")))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "Invalid scope: "+r.PostForm.Get("scope"))
		return
	}
	cl := x.claims(c, granted)
	raw, err := x.Sign(cl)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": raw,
		"token_type":   "bearer",
		"expires_in":   int(x.cfg.TokenLifetime/time.Second) - 1,
		"scope":        strings.Join(granted, " "),
		"jti":          cl["jti"],
	})
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func (x *XSUAA) client(id string) (XSUAAClient, bool) {
	for _, c := range x.cfg.Clients {
		if c.ClientID == id {
			return c, true
		}
	}
	return XSUAAClient{}, false
}

// claims builds the claims of a client_credentials token the way XSUAA
// shapes them. aud is the caller's client ID plus the namespaces of the
// granted scopes.
func (x *XSUAA) claims(c XSUAAClient, scopes []string) jwt.MapClaims {
	now := x.cfg.Now()
	aud := []string{c.ClientID}
	for _, sc := range scopes {
		ns := sc
		if i := strings.LastIndexByte(sc, '.'); i >= 0 {
			ns = sc[:i]
		}
		if !slices.Contains(aud, ns) {
			aud = append(aud, ns)
		}
	}
	var jti [16]byte
	_, _ = rand.Read(jti[:])
	return jwt.MapClaims{
		"jti":        hex.EncodeToString(jti[:]),
		"sub":        c.ClientID,
		"client_id":  c.ClientID,
		"cid":        c.ClientID,
		"azp":        c.ClientID,
		"grant_type": "client_credentials",
		"scope":      append([]string{}, scopes...),
		"aud":        aud,
		// XSUAA's internal issuer literal, not a reachable URL.
		"iss": "http://" + x.cfg.Subdomain + ".localhost:8080/uaa/oauth/token",
		"zid": x.cfg.ZoneID,
		"ext_attr": map[string]string{
			"enhancer":     "XSUAA",
			"subaccountid": x.cfg.ZoneID,
			"zdn":          x.cfg.Subdomain,
		},
		"iat": now.Unix(),
		"exp": now.Add(x.cfg.TokenLifetime).Unix(),
	}
}
