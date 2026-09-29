package ginpingo

import (
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/internal/fwdheader"
)

// isMutatingMethod returns true for the four HTTP methods that SAP's ICF
// typically gates with CSRF: POST, PUT, DELETE and PATCH. Every other
// method (GET, HEAD, OPTIONS, and extension methods such as LINK or LOCK)
// takes the read path without the handshake.
func isMutatingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// ProxyHandler is a Gin handler exposing /:destination/*path as a
// transparent pass-through onto svc. Useful for exploration and
// debugging; production handlers should wrap
// btpingo.Service.CallOnPremise / CallOnPremiseMutating with
// endpoint-specific logic.
//
// The method gate below routes mutating requests through
// CallOnPremiseMutating so that SAP endpoints enforcing CSRF work
// out of the box — a bare POST / PUT / DELETE / PATCH against
// <route>/<destination>/sap/bc/adt/... would otherwise fail with
// 403 X-CSRF-Token: Required on every call.
func ProxyHandler(svc *btpingo.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		destName := c.Param("destination")
		suffix := c.Param("path")

		var (
			resp *http.Response
			err  error
		)
		if isMutatingMethod(c.Request.Method) {
			resp, err = svc.CallOnPremiseMutating(c.Request.Context(), destName, c.Request.Method, suffix, c.Request.Header, c.Request.Body)
		} else {
			resp, err = svc.CallOnPremise(c.Request.Context(), destName, c.Request.Method, suffix, c.Request.Header, c.Request.Body)
		}
		if err != nil {
			AbortError(c, http.StatusBadGateway, btpingo.CodeUpstreamUnreachable,
				"on-premise call failed", err)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		for k, vs := range resp.Header {
			if fwdheader.Skip(k) {
				continue
			}
			for _, v := range vs {
				c.Writer.Header().Add(k, v)
			}
		}
		c.Writer.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(c.Writer, resp.Body); err != nil {
			// Almost always a client disconnect mid-stream; nothing for
			// operators to act on. Emit at DEBUG so a developer chasing a
			// specific cut-off case can raise the level locally, but the
			// production INFO stream stays quiet on normal disconnects.
			// Deliberately not WARN: this package does not use that level —
			// a condition either needs operator action or it does not.
			slog.DebugContext(c.Request.Context(),
				"copying on-prem response to client failed",
				"destination", destName,
				"err", err,
			)
		}
	}
}
