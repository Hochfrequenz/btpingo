// Package fwdheader holds the header-forwarding filter shared by
// btpingo's core on-prem call path and ginpingo's ProxyHandler. It is
// importable only from inside this module (internal/), which is why
// the filter is not part of either package's public API even though
// both need the exact same behaviour.
package fwdheader

import (
	"net/http"
	"strings"
)

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

// Forward copies the headers of src that may travel to the on-prem
// system into dst: everything except [Skip] names, and Cookie reduced
// to the SAP session cookies by [FilterCookies]. It is the one place
// that defines what btpingo.Service sends from the inbound headers, so
// fakes of the on-prem call (btpingotest) cannot drift from it.
func Forward(dst, src http.Header) {
	for k, vs := range src {
		if strings.EqualFold(k, "Cookie") {
			// Cookies get per-cookie filtering: other session cookies
			// (JSESSIONID etc.) are dropped, SAP session cookies
			// (SAP_SESSIONID_* / sap-usercontext) pass through so
			// CallOnPremiseMutating can inject them for the CSRF handshake.
			for _, v := range vs {
				if kept := FilterCookies(v); kept != "" {
					dst.Add("Cookie", kept)
				}
			}
			continue
		}
		if Skip(k) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// FilterCookies reads one inbound `Cookie:` header value and
// returns a `Cookie:` value containing only cookies that are safe to
// forward to the SAP side:
//
//   - SAP_SESSIONID_<sid>_<client> — the SAP session cookie set by the
//     server after a CSRF-fetch; mutating calls must echo it back or
//     the ICF rejects them.
//   - sap-usercontext — SAP's per-user context handle.
//
// Everything else (approuter's JSESSIONID, tracking cookies, etc.) is
// dropped. Empty return value means no `Cookie:` header should travel
// at all — callers must skip the Add in that case.
func FilterCookies(cookieHeader string) string {
	var kept []string
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if strings.HasPrefix(name, "SAP_SESSIONID_") || name == "sap-usercontext" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "; ")
}
