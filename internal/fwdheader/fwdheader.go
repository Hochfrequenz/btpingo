// Package fwdheader holds the header-forwarding filter shared by
// btpingo's core on-prem call path and ginpingo's ProxyHandler. It is
// importable only from inside this module (internal/), which is why
// the filter is not part of either package's public API even though
// both need the exact same behaviour.
package fwdheader

import "strings"

// Skip reports whether a header must not be forwarded from the
// inbound request (e.g. via the approuter) to the on-prem call:
//
//   - Authorization: the destination's authenticator sets the right value;
//     the inbound JWT is not a credential the on-prem system understands.
//   - Proxy-Authorization: the on-prem transport sets it (http targets) or
//     strips it (https targets) itself.
//   - hop-by-hop (Connection, Keep-Alive, TE, Trailer, Transfer-Encoding,
//     Upgrade, Proxy-Connect) per RFC 7230; forwarding them would confuse
//     the Connectivity proxy.
//   - Host: the net/http library derives the right value from the target
//     URL; forwarding the inbound Host breaks virtual-host routing on
//     the SAP side.
//
// Cookie is deliberately NOT in the drop list: btpingo does per-cookie
// filtering of Cookie headers itself so SAP session cookies
// (SAP_SESSIONID_* / sap-usercontext) can flow through as part of the
// CSRF handshake in CallOnPremiseMutating, while other cookies
// (e.g. the approuter's JSESSIONID) are still dropped.
//
// Used by both btpingo's core on-prem call path and
// [github.com/hochfrequenz/btpingo/ginpingo.ProxyHandler], so the
// response headers ProxyHandler relays back to the client go through
// the same filter as the request headers the core forwards on.
func Skip(name string) bool {
	switch strings.ToLower(name) {
	case "authorization",
		"connection",
		"keep-alive",
		"proxy-authorization",
		"proxy-connect",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"host":
		return true
	}
	return false
}
