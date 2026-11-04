package testkit

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/btpingotest"
)

// JWKSFixture is a btpingotest mock XSUAA behind an httptest server.
// Tests mint tokens with arbitrary claims via Mint and point a
// validator at the server via NewValidator.
type JWKSFixture struct {
	xsuaa  *btpingotest.XSUAA
	server *httptest.Server
}

// NewJWKSFixture generates a fresh RSA keypair and serves its JWKS.
func NewJWKSFixture(t *testing.T) *JWKSFixture {
	t.Helper()
	x, err := btpingotest.NewXSUAA(btpingotest.XSUAAConfig{XSAppName: "testkit", AppClientID: "testkit"})
	if err != nil {
		t.Fatalf("new mock xsuaa: %v", err)
	}
	srv := httptest.NewServer(x)
	t.Cleanup(srv.Close)
	return &JWKSFixture{xsuaa: x, server: srv}
}

// Mint signs claims with the fixture's key and returns the raw JWT.
func (f *JWKSFixture) Mint(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	raw, err := f.xsuaa.Sign(claims)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return raw
}

// NewValidator returns a validator fetching the fixture's JWKS from its
// server. clientID is the value tokens must carry in their "aud" claim
// to be accepted. The second result is the server's base URL.
func NewValidator(t *testing.T, f *JWKSFixture, clientID string) (*btpingo.JWTValidator, string) {
	t.Helper()
	creds := f.xsuaa.Credentials(f.server.URL)
	creds.ClientID = clientID
	v, err := btpingo.NewJWTValidator(context.Background(), creds)
	if err != nil {
		t.Fatalf("new jwt validator: %v", err)
	}
	return v, f.server.URL
}
