package onprem_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo/internal/onprem"
)

var errCross = errors.New("cross")

func reqTo(raw string) *http.Request {
	u, _ := url.Parse(raw)
	return &http.Request{URL: u}
}

func Test_RedirectPolicy(t *testing.T) {
	check := onprem.RedirectPolicy(errCross)
	via := func(n int) []*http.Request {
		v := make([]*http.Request, n)
		for i := range v {
			v[i] = reqTo("http://sap.example:8000/a")
		}
		return v
	}
	cases := []struct {
		name    string
		to      string
		hops    int
		wantErr string // "", "cross", "limit"
	}{
		{"same origin", "http://sap.example:8000/b", 1, ""},
		{"host case", "http://SAP.Example:8000/b", 1, ""},
		{"other host", "http://elsewhere.example/b", 1, "cross"},
		{"other scheme", "https://sap.example:8000/b", 1, "cross"},
		{"other port", "http://sap.example:9000/b", 1, "cross"},
		{"limit", "http://sap.example:8000/b", onprem.MaxRedirects, "limit"},
		{"cross beats limit", "http://elsewhere.example/b", onprem.MaxRedirects, "cross"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := check(reqTo(c.to), via(c.hops))
			switch c.wantErr {
			case "":
				then.AssertThat(t, err, is.Nil())
			case "cross":
				then.AssertThat(t, errors.Is(err, errCross), is.True())
			default:
				then.AssertThat(t, err, is.Not(is.Nil()))
				then.AssertThat(t, errors.Is(err, errCross), is.False())
			}
		})
	}
}

func Test_Retry401(t *testing.T) {
	var nilBody io.Reader
	cases := []struct {
		name   string
		status int
		body   io.Reader
		want   bool
	}{
		{"401 no body", 401, nilBody, true},
		{"401 with body", 401, strings.NewReader("x"), false},
		{"403 no body", 403, nilBody, false},
		{"200 no body", 200, nilBody, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			then.AssertThat(t, onprem.Retry401(c.status, c.body), is.EqualTo(c.want))
		})
	}
}
