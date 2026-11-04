// Package pathsuffix holds the path-suffix rules of btpingo.Service.CallOnPremise,
// shared with btpingotest.HandlerCaller so the fake rejects exactly what
// the real service rejects.
package pathsuffix

import (
	"fmt"
	"strings"
)

// Check rejects traversal attempts at the edge: a user-supplied `..`
// would otherwise travel unchanged into the on-prem URL, where some SAP
// HTTP frontends resolve it against the destination root and serve a
// resource the destination's author never meant to expose. The same
// risk applies to percent-encoded variants (`%2e%2e`, mixed case, ...)
// because some frontends decode before applying path-resolution rules.
// Rather than chase decoder quirks, any `%` is rejected outright.
func Check(s string) error {
	if strings.Contains(s, "..") {
		return fmt.Errorf("path suffix %q contains '..'; traversal is not allowed", s)
	}
	if strings.Contains(s, "%") {
		return fmt.Errorf("path suffix %q contains '%%'; percent-encoded path segments are not allowed", s)
	}
	return nil
}
