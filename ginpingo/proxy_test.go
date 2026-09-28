package ginpingo_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
	"github.com/gin-gonic/gin"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/ginpingo"
	"github.com/hochfrequenz/btpingo/internal/testkit"
)

func Test_Service_ProxyHandler_EndToEnd(t *testing.T) {
	s := testkit.NewBTPStack(t, "placeholder")
	s = testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,"Authentication":"NoAuthentication","ProxyType":"OnPremise"}
	}`, s.OnPrem.URL))
	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Any("/api/sap/:destination/*path", ginpingo.ProxyHandler(svc))

	req := httptest.NewRequest(http.MethodGet, "/api/sap/D/whatever", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
	then.AssertThat(t, strings.Contains(w.Body.String(), `"ok":true`), is.True())
}

func Test_Service_ProxyHandler_Returns502OnLookupFail(t *testing.T) {
	s := testkit.NewBTPStack(t, "placeholder")
	s.Dest.Close()
	s.Dest = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(s.Dest.Close)
	s.Env.Dest.URI = s.Dest.URL

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Any("/api/sap/:destination/*path", ginpingo.ProxyHandler(svc))

	req := httptest.NewRequest(http.MethodGet, "/api/sap/Missing/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	then.AssertThat(t, w.Code, is.EqualTo(http.StatusBadGateway))
}
