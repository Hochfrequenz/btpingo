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

	// TokenLifetime is the lifetime of the tokens the mock issues
	// (XSUAA's default for access tokens is 12 h).
	TokenLifetime = 12 * time.Hour

	// KeyID is the "kid" of the mock's signing key.
	KeyID = "mock-key-1"

	defaultZoneID = "mock-zone"
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
	// Clients are the callers that may fetch tokens.
	Clients []XSUAAClient
	// ZoneID is the identity zone ("zid" claim). Default "mock-zone".
	ZoneID string
	// Now is the clock for iat/exp. Default time.Now.
	Now func() time.Time
}

// XSUAA is a mock of the XSUAA endpoints a btpingo-based service uses:
// the JWKS (GET /token_keys) and the client_credentials grant
// (POST /oauth/token). It is an http.Handler that can be mounted on any
// mux; it runs no server of its own. It is meant for tests and local
// mocks only and must never be wired into a production binary.
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
	cfg.Clients = slices.Clone(cfg.Clients)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("btpingotest: generate rsa key: %w", err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": KeyID,
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
// secret if it is in the client list, otherwise a fixed placeholder.
func (x *XSUAA) Credentials(baseURL string) *btpingo.XSUAACredentials {
	secret := "mock-secret"
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
// client_credentials grant would, without HTTP.
func (x *XSUAA) MintToken(clientID string) (string, error) {
	c, ok := x.client(clientID)
	if !ok {
		return "", fmt.Errorf("btpingotest: unknown client %q", clientID)
	}
	return x.Sign(x.claims(c))
}

// Sign signs arbitrary claims with the mock's key (RS256, header kid), for
// tests of rejected tokens (expired, foreign audience, ...).
func (x *XSUAA) Sign(claims jwt.Claims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = KeyID
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
	cl := x.claims(c)
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
		"expires_in":   int(TokenLifetime / time.Second),
		"scope":        strings.Join(c.Scopes, " "),
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
// shapes them.
func (x *XSUAA) claims(c XSUAAClient) jwt.MapClaims {
	now := x.cfg.Now()
	aud := []string{x.cfg.AppClientID}
	if c.ClientID != x.cfg.AppClientID {
		aud = append(aud, c.ClientID)
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
		"scope":      append([]string{}, c.Scopes...),
		"aud":        aud,
		// XSUAA's internal issuer literal, not a reachable URL.
		"iss": "http://" + x.cfg.ZoneID + ".localhost:8080/uaa/oauth/token",
		"zid": x.cfg.ZoneID,
		"iat": now.Unix(),
		"exp": now.Add(TokenLifetime).Unix(),
	}
}
