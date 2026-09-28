package testkit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
)

// JWKSFixture stands up an RSA keypair and an httptest server that
// serves the matching JWKS. Tests mint tokens with the key and point a
// validator at the server via NewValidator.
type JWKSFixture struct {
	key    *rsa.PrivateKey
	server *httptest.Server
	kid    string
}

// NewJWKSFixture generates a fresh RSA keypair and serves its JWKS.
func NewJWKSFixture(t *testing.T) *JWKSFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	kid := "test-key"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, kid, n, e)
	}))
	t.Cleanup(srv.Close)
	return &JWKSFixture{key: key, server: srv, kid: kid}
}

// Mint signs claims with the fixture's key and returns the raw JWT.
func (f *JWKSFixture) Mint(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	raw, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return raw
}

// NewValidator stands up a server that serves JWKS at /token_keys using
// the fixture's key, and returns a validator pointed at it. clientID is
// the value tokens must carry in their "aud" claim to be accepted.
func NewValidator(t *testing.T, f *JWKSFixture, clientID string) (*btpingo.JWTValidator, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token_keys", func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(f.server.URL)
		if err != nil {
			http.Error(w, "fake jwks: upstream fetch failed", http.StatusInternalServerError)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.Copy(w, resp.Body)
	})
	wrapper := httptest.NewServer(mux)
	t.Cleanup(wrapper.Close)

	v, err := btpingo.NewJWTValidator(context.Background(), &btpingo.XSUAACredentials{URL: wrapper.URL, ClientID: clientID})
	if err != nil {
		t.Fatalf("new jwt validator: %v", err)
	}
	return v, wrapper.URL
}
