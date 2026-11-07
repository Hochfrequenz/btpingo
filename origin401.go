package btpingo

import "net/http"

// Origin401Kind says who most likely answered a 401 from CallOnPremise.
type Origin401Kind int

const (
	// Origin401None: the response is not a 401.
	Origin401None Origin401Kind = iota
	// Origin401OnPrem: the 401 carries a WWW-Authenticate challenge, which
	// RFC 9110 requires of an origin server's 401. The on-prem system (ICF
	// node) rejected the destination's credentials, e.g. a Basic logon.
	Origin401OnPrem
	// Origin401Proxy: the 401 carries no WWW-Authenticate challenge. The
	// connectivity proxy most likely rejected btpingo's bearer token
	// (self-healing: the next call fetches a fresh one). A non-compliant
	// on-prem system that omits the challenge lands here too.
	Origin401Proxy
)

func (k Origin401Kind) String() string {
	switch k {
	case Origin401OnPrem:
		return "onprem"
	case Origin401Proxy:
		return "proxy"
	default:
		return "none"
	}
}

// Origin401 classifies a response from CallOnPremise by the headers alone,
// without reading the body. It is a heuristic, not a signal from SAP:
// the connectivity proxy answers with no WWW-Authenticate, an ICF node
// with one (Basic realm=...). A caller that must not act on a bearer
// race (e.g. open a circuit breaker to protect the SAP user from a lock)
// should act only on Origin401OnPrem.
//
// The proxy's actual answer has not been verified against a live system
// and must be checked before relying on this. 407 and 403 are not
// classified (returns Origin401None).
func Origin401(resp *http.Response) Origin401Kind {
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return Origin401None
	}
	if len(resp.Header.Values("WWW-Authenticate")) > 0 {
		return Origin401OnPrem
	}
	return Origin401Proxy
}
