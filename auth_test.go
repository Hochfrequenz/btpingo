package btpingo_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/internal/testkit"
)

func Test_JWTValidator_AcceptsValidToken(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, issuer := testkit.NewValidator(t, f, "GoApp")

	raw := f.Mint(t, jwt.MapClaims{
		"iss": issuer,
		"aud": "GoApp",
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "user-1",
	})
	claims, err := v.Parse(raw)
	then.AssertThat(t, err, is.Nil())
	sub, _ := claims["sub"].(string)
	then.AssertThat(t, sub, is.EqualTo("user-1"))
}

func Test_JWTValidator_RejectsWrongAudience(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, issuer := testkit.NewValidator(t, f, "GoApp")
	raw := f.Mint(t, jwt.MapClaims{
		"iss": issuer,
		"aud": "SomeoneElse",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err := v.Parse(raw)
	then.AssertThat(t, err, is.Not(is.Nil()))
}

// With the iss check dropped (see NewJWTValidator doc), the actual security
// boundary on "was this token minted by our XSUAA tenant?" is signature
// verification against the JWKS URL pinned at construction time. This test
// mints a token signed with a different key (and a kid the JWKS does not
// advertise) to confirm the validator rejects it.
func Test_JWTValidator_RejectsTokenSignedByUnknownKey(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, _ := testkit.NewValidator(t, f, "GoApp")

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	then.AssertThat(t, err, is.Nil())

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": "GoApp",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "key-not-in-jwks"
	raw, err := tok.SignedString(other)
	then.AssertThat(t, err, is.Nil())

	_, err = v.Parse(raw)
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_JWTValidator_RejectsExpired(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, issuer := testkit.NewValidator(t, f, "GoApp")
	raw := f.Mint(t, jwt.MapClaims{
		"iss": issuer,
		"aud": "GoApp",
		// Past the TokenRefreshLeeway window.
		"exp": time.Now().Add(-2 * time.Minute).Unix(),
	})
	_, err := v.Parse(raw)
	then.AssertThat(t, err, is.Not(is.Nil()))
	then.AssertThat(t, strings.Contains(err.Error(), "expired") || strings.Contains(err.Error(), "exp"), is.True())
}

// Test_JWTValidator_RejectsFutureIssuedAt pins the doc comment's claim
// that iat is validated: jwt/v5 only checks it with jwt.WithIssuedAt()
// passed explicitly, so a token claiming to be issued two hours in the
// future must be rejected.
func Test_JWTValidator_RejectsFutureIssuedAt(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, issuer := testkit.NewValidator(t, f, "GoApp")
	raw := f.Mint(t, jwt.MapClaims{
		"iss": issuer,
		"aud": "GoApp",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(2 * time.Hour).Unix(),
	})
	_, err := v.Parse(raw)
	then.AssertThat(t, err, is.Not(is.Nil()))
}

// Test_JWTValidator_AcceptsCurrentIssuedAt pairs with the future-iat
// test: a token issued now must still pass once iat is validated.
func Test_JWTValidator_AcceptsCurrentIssuedAt(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, issuer := testkit.NewValidator(t, f, "GoApp")
	raw := f.Mint(t, jwt.MapClaims{
		"iss": issuer,
		"aud": "GoApp",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sub": "user-1",
	})
	claims, err := v.Parse(raw)
	then.AssertThat(t, err, is.Nil())
	sub, _ := claims["sub"].(string)
	then.AssertThat(t, sub, is.EqualTo("user-1"))
}

// Test_JWTValidator_AcceptsIssuedAtWithinLeeway checks the other edge of
// the same leeway that TokenRefreshLeeway grants exp/nbf: an iat a few
// seconds ahead of now (clock skew between the issuer and this host, not
// a forged future token) must still be accepted.
func Test_JWTValidator_AcceptsIssuedAtWithinLeeway(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, issuer := testkit.NewValidator(t, f, "GoApp")
	raw := f.Mint(t, jwt.MapClaims{
		"iss": issuer,
		"aud": "GoApp",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(10 * time.Second).Unix(),
		"sub": "user-1",
	})
	claims, err := v.Parse(raw)
	then.AssertThat(t, err, is.Nil())
	sub, _ := claims["sub"].(string)
	then.AssertThat(t, sub, is.EqualTo("user-1"))
}

func Test_JWTValidator_RejectsHS256(t *testing.T) {
	f := testkit.NewJWKSFixture(t)
	v, _ := testkit.NewValidator(t, f, "GoApp")
	// Sign with HMAC — the parser must refuse the algorithm before ever
	// reaching key lookup (classic alg-confusion defence).
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": "GoApp",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	raw, err := tok.SignedString([]byte("secret"))
	then.AssertThat(t, err, is.Nil())
	_, err = v.Parse(raw)
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_JWTValidator_RequiresURLAndClientID(t *testing.T) {
	// Missing URL.
	_, err := btpingo.NewJWTValidator(context.Background(), &btpingo.XSUAACredentials{ClientID: "c"})
	then.AssertThat(t, err, is.Not(is.Nil()))

	// Missing ClientID.
	_, err = btpingo.NewJWTValidator(context.Background(), &btpingo.XSUAACredentials{URL: "https://u"})
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_JWTValidator_RequiresNonNil(t *testing.T) {
	_, err := btpingo.NewJWTValidator(context.Background(), nil)
	then.AssertThat(t, err, is.Not(is.Nil()))
}
