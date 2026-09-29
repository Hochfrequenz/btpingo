package btpingo

import (
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
)

// Internal test covers filterForwardedCookies, an unexported helper
// that is load-bearing for the CSRF path: it decides whether an
// inbound Cookie header survives the forward. It is small enough to
// keep behavior frozen with a direct unit test — an external test
// would have to drive a full HTTP stack to observe the same outcome.
// (isMutatingMethod moved to ginpingo along with ProxyHandler, the
// only thing that used it.)

func Test_filterForwardedCookies(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"only approuter cookie — dropped", "JSESSIONID=foo", ""},
		{"only SAP session — kept", "SAP_SESSIONID_ABC_100=abc", "SAP_SESSIONID_ABC_100=abc"},
		{"only sap-usercontext — kept", "sap-usercontext=sapclient100", "sap-usercontext=sapclient100"},
		{"mixed — approuter dropped, SAP kept",
			"JSESSIONID=foo; SAP_SESSIONID_XYZ_100=s1; sap-usercontext=u1",
			"SAP_SESSIONID_XYZ_100=s1; sap-usercontext=u1"},
		{"double spaces around separator",
			"JSESSIONID=foo;   SAP_SESSIONID_ABC_100=abc",
			"SAP_SESSIONID_ABC_100=abc"},
		{"empty segment between semicolons",
			";; SAP_SESSIONID_ABC_100=abc ;;",
			"SAP_SESSIONID_ABC_100=abc"},
		{"cookie without value — still checked by name",
			"SAP_SESSIONID_NOVAL",
			"SAP_SESSIONID_NOVAL"},
		{"lowercase sap_sessionid — dropped (case-sensitive by design)",
			"sap_sessionid_abc_100=abc",
			""},
		{"partial-prefix match must NOT pass",
			"SAP_SESSION=nope",
			""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := filterForwardedCookies(c.in)
			then.AssertThat(t, got, is.EqualTo(c.want))
		})
	}
}
