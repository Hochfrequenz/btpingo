package btpingotest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/btpingotest"
	"github.com/hochfrequenz/btpingo/ginpingo"
)

const (
	appName     = "demo!t1"
	appClientID = "sb-demo!t1"
	userScope   = "demo!t1.User"
)

func newXSUAA(t *testing.T) (*btpingotest.XSUAA, *httptest.Server) {
	t.Helper()
	x, err := btpingotest.NewXSUAA(btpingotest.XSUAAConfig{
		XSAppName:   appName,
		AppClientID: appClientID,
		Clients: []btpingotest.XSUAAClient{
			{ClientID: appClientID, Secret: "secret", Scopes: []string{userScope}},
			{ClientID: "noscope", Secret: "secret2"},
		},
	})
	then.AssertThat(t, err, is.Nil())
	srv := httptest.NewServer(x)
	t.Cleanup(srv.Close)
	return x, srv
}

// apiRouter is the production auth chain: real validator, JWT, RequireScope.
func apiRouter(t *testing.T, creds *btpingo.XSUAACredentials) *gin.Engine {
	t.Helper()
	v, err := btpingo.NewJWTValidator(context.Background(), creds)
	then.AssertThat(t, err, is.Nil())
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.JWT(v), ginpingo.RequireScope(userScope))
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func fetchToken(t *testing.T, base string, setup func(*http.Request), form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(form.Encode()))
	then.AssertThat(t, err, is.Nil())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if setup != nil {
		setup(req)
	}
	resp, err := http.DefaultClient.Do(req)
	then.AssertThat(t, err, is.Nil())
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func Test_XSUAA_CredentialsValidate(t *testing.T) {
	x, srv := newXSUAA(t)
	creds := x.Credentials(srv.URL + "/")
	var errs []string
	creds.Validate(&errs)
	then.AssertThat(t, len(errs), is.EqualTo(0))
	then.AssertThat(t, creds.JWKSURL(), is.EqualTo(srv.URL+"/token_keys"))
	then.AssertThat(t, creds.ClientID, is.EqualTo(appClientID))
}

func Test_XSUAA_TokenThroughRealAuthChain(t *testing.T) {
	x, srv := newXSUAA(t)
	r := apiRouter(t, x.Credentials(srv.URL))

	basic := func(id, secret string) func(*http.Request) {
		return func(req *http.Request) { req.SetBasicAuth(id, secret) }
	}
	cases := []struct {
		name   string
		setup  func(*http.Request)
		form   url.Values
		status int // of the API call
	}{
		{"basic, with scope", basic(appClientID, "secret"), url.Values{"grant_type": {"client_credentials"}}, http.StatusOK},
		{"form, with scope", nil, url.Values{"grant_type": {"client_credentials"}, "client_id": {appClientID}, "client_secret": {"secret"}}, http.StatusOK},
		{"basic, without scope", basic("noscope", "secret2"), url.Values{"grant_type": {"client_credentials"}}, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := fetchToken(t, srv.URL, c.setup, c.form)
			then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusOK))
			var body struct {
				AccessToken string `json:"access_token"`
				TokenType   string `json:"token_type"`
				ExpiresIn   int    `json:"expires_in"`
			}
			then.AssertThat(t, json.NewDecoder(resp.Body).Decode(&body), is.Nil())
			then.AssertThat(t, body.TokenType, is.EqualTo("bearer"))
			then.AssertThat(t, body.ExpiresIn, is.EqualTo(12*3600))

			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+body.AccessToken)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			then.AssertThat(t, w.Code, is.EqualTo(c.status))
		})
	}

	t.Run("no token", func(t *testing.T) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		then.AssertThat(t, w.Code, is.EqualTo(http.StatusUnauthorized))
	})
}

func Test_XSUAA_MintToken(t *testing.T) {
	x, srv := newXSUAA(t)
	r := apiRouter(t, x.Credentials(srv.URL))
	for _, c := range []struct {
		client string
		status int
	}{{appClientID, http.StatusOK}, {"noscope", http.StatusForbidden}} {
		t.Run(c.client, func(t *testing.T) {
			tok, err := x.MintToken(c.client)
			then.AssertThat(t, err, is.Nil())
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			then.AssertThat(t, w.Code, is.EqualTo(c.status))
		})
	}
	_, err := x.MintToken("nobody")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_XSUAA_TokenShape(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	x, err := btpingotest.NewXSUAA(btpingotest.XSUAAConfig{
		XSAppName: appName, AppClientID: appClientID, ZoneID: "zone-1",
		Clients: []btpingotest.XSUAAClient{{ClientID: "caller", Secret: "s", Scopes: []string{userScope, "demo!t1.Admin"}}},
		Now:     func() time.Time { return now },
	})
	then.AssertThat(t, err, is.Nil())
	raw, err := x.MintToken("caller")
	then.AssertThat(t, err, is.Nil())

	claims := jwt.MapClaims{}
	tok, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, str(tok.Header["alg"]), is.EqualTo("RS256"))
	then.AssertThat(t, str(tok.Header["kid"]), is.EqualTo(btpingotest.KeyID))

	aud, err := claims.GetAudience()
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, []string(aud), is.EqualTo([]string{appClientID, "caller"}))
	then.AssertThat(t, str(claims["client_id"]), is.EqualTo("caller"))
	then.AssertThat(t, str(claims["cid"]), is.EqualTo("caller"))
	then.AssertThat(t, str(claims["grant_type"]), is.EqualTo("client_credentials"))
	then.AssertThat(t, str(claims["zid"]), is.EqualTo("zone-1"))
	then.AssertThat(t, str(claims["iss"]), is.EqualTo("http://zone-1.localhost:8080/uaa/oauth/token"))
	then.AssertThat(t, btpingo.ScopesFromClaims(claims), is.EqualTo([]string{userScope, "demo!t1.Admin"}))
	then.AssertThat(t, num(claims["iat"]), is.EqualTo(float64(now.Unix())))
	then.AssertThat(t, num(claims["exp"]), is.EqualTo(float64(now.Add(12*time.Hour).Unix())))
}

func Test_XSUAA_TokenEndpointErrors(t *testing.T) {
	_, srv := newXSUAA(t)
	grant := url.Values{"grant_type": {"client_credentials"}}
	basic := func(id, secret string) func(*http.Request) {
		return func(req *http.Request) { req.SetBasicAuth(id, secret) }
	}
	cases := []struct {
		name   string
		setup  func(*http.Request)
		form   url.Values
		status int
		errMsg string
	}{
		{"unknown client", basic("nobody", "secret"), grant, http.StatusUnauthorized, "unauthorized"},
		{"wrong secret", basic(appClientID, "wrong"), grant, http.StatusUnauthorized, "unauthorized"},
		{"empty secret", basic(appClientID, ""), grant, http.StatusUnauthorized, "unauthorized"},
		{"no credentials", nil, grant, http.StatusUnauthorized, "unauthorized"},
		{"form wrong secret", nil, url.Values{"grant_type": {"client_credentials"}, "client_id": {appClientID}, "client_secret": {"x"}}, http.StatusUnauthorized, "unauthorized"},
		{"basic wins over form", basic(appClientID, "wrong"), url.Values{"grant_type": {"client_credentials"}, "client_id": {appClientID}, "client_secret": {"secret"}}, http.StatusUnauthorized, "unauthorized"},
		{"wrong grant", basic(appClientID, "secret"), url.Values{"grant_type": {"password"}}, http.StatusBadRequest, "unsupported_grant_type"},
		{"missing grant", basic(appClientID, "secret"), nil, http.StatusBadRequest, "unsupported_grant_type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := fetchToken(t, srv.URL, c.setup, c.form)
			then.AssertThat(t, resp.StatusCode, is.EqualTo(c.status))
			var body map[string]string
			then.AssertThat(t, json.NewDecoder(resp.Body).Decode(&body), is.Nil())
			then.AssertThat(t, body["error"], is.EqualTo(c.errMsg))
		})
	}

	t.Run("GET is not allowed", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/oauth/token")
		then.AssertThat(t, err, is.Nil())
		_ = resp.Body.Close()
		then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusMethodNotAllowed))
	})
	t.Run("unknown path", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/nope")
		then.AssertThat(t, err, is.Nil())
		_ = resp.Body.Close()
		then.AssertThat(t, resp.StatusCode, is.EqualTo(http.StatusNotFound))
	})
}

func Test_XSUAA_JWKS(t *testing.T) {
	_, srv := newXSUAA(t)
	resp, err := http.Get(srv.URL + "/token_keys")
	then.AssertThat(t, err, is.Nil())
	defer func() { _ = resp.Body.Close() }()
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	then.AssertThat(t, json.NewDecoder(resp.Body).Decode(&jwks), is.Nil())
	then.AssertThat(t, len(jwks.Keys), is.EqualTo(1))
	then.AssertThat(t, jwks.Keys[0]["kid"], is.EqualTo(btpingotest.KeyID))
	then.AssertThat(t, jwks.Keys[0]["alg"], is.EqualTo("RS256"))
}

func Test_XSUAA_Register_OnForeignMux(t *testing.T) {
	x, _ := newXSUAA(t)
	mux := http.NewServeMux()
	x.Register(mux)
	mux.HandleFunc("/other", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	_, err := btpingo.NewJWTValidator(context.Background(), x.Credentials(srv.URL))
	then.AssertThat(t, err, is.Nil())
}

func Test_XSUAA_RejectsForeignAndExpiredTokens(t *testing.T) {
	x, srv := newXSUAA(t)
	r := apiRouter(t, x.Credentials(srv.URL))
	now := time.Now()
	good := func() jwt.MapClaims {
		return jwt.MapClaims{
			"aud": []string{appClientID}, "scope": []string{userScope},
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		}
	}
	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
		status int
	}{
		{"control", func(jwt.MapClaims) {}, http.StatusOK},
		{"foreign app client id", func(c jwt.MapClaims) { c["aud"] = []string{"sb-other!t9"} }, http.StatusUnauthorized},
		{"expired", func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Hour).Unix() }, http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := good()
			c.mutate(claims)
			raw, err := x.Sign(claims)
			then.AssertThat(t, err, is.Nil())
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+raw)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			then.AssertThat(t, w.Code, is.EqualTo(c.status))
		})
	}

	t.Run("token of another mock instance (other key)", func(t *testing.T) {
		other, _ := newXSUAA(t)
		raw, err := other.MintToken(appClientID)
		then.AssertThat(t, err, is.Nil())
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		then.AssertThat(t, w.Code, is.EqualTo(http.StatusUnauthorized))
	})
}

func Test_NewXSUAA_RejectsBadConfig(t *testing.T) {
	cases := map[string]btpingotest.XSUAAConfig{
		"no app":        {},
		"no secret":     {XSAppName: "a", AppClientID: "b", Clients: []btpingotest.XSUAAClient{{ClientID: "c"}}},
		"duplicate":     {XSAppName: "a", AppClientID: "b", Clients: []btpingotest.XSUAAClient{{ClientID: "c", Secret: "s"}, {ClientID: "c", Secret: "s"}}},
		"no app client": {XSAppName: "a"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := btpingotest.NewXSUAA(cfg)
			then.AssertThat(t, err, is.Not(is.Nil()))
		})
	}
}

func str(v any) string { s, _ := v.(string); return s }

func num(v any) float64 { f, _ := v.(float64); return f }
