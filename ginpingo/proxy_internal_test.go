package ginpingo

import (
	"net/http"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
)

// Internal test covers isMutatingMethod, an unexported helper that is
// load-bearing for the CSRF path: it decides whether ProxyHandler
// takes the CSRF path. It is small enough to keep behavior frozen with
// a direct unit test — an external test would have to drive a full
// HTTP stack to observe the same outcome.
func Test_isMutatingMethod(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{http.MethodPost, true},
		{http.MethodPut, true},
		{http.MethodDelete, true},
		{http.MethodPatch, true},
		// Case-insensitive handling — clients sometimes lowercase.
		{"post", true},
		{"Put", true},
		// Read methods — must NOT trigger the CSRF path.
		{http.MethodGet, false},
		{http.MethodHead, false},
		{http.MethodOptions, false},
		// Unknown / exotic — default to false so an unexpected
		// method doesn't accidentally skip the read-path retry
		// logic. LINK / LOCK / MKCOL are deliberately outside the
		// CSRF gate; adding them means changing isMutatingMethod.
		{"LINK", false},
		{"LOCK", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			then.AssertThat(t, isMutatingMethod(c.method), is.EqualTo(c.want))
		})
	}
}
