# BTPinGo 🐧

![Unittests](https://github.com/hochfrequenz/btpingo/actions/workflows/test.yml/badge.svg)
![coverage](https://github.com/hochfrequenz/btpingo/actions/workflows/coverage.yml/badge.svg)
![golangci-lint](https://github.com/hochfrequenz/btpingo/actions/workflows/golangci-lint.yml/badge.svg)

A Go client for apps on **SAP BTP Cloud Foundry** that call an **on-premise SAP system**. It covers:

- **XSUAA:** it validates the JWTs your app receives.
- **Destination service:** it looks up the destination by name.
- **Connectivity service and Cloud Connector:** it fetches the Destination-service and Connectivity tokens a call needs and routes the call through the Connectivity proxy. It handles the CSRF handshake for mutating calls and the destination's own authentication.

SAP's Cloud SDK covers this for Java and JavaScript only. Without it, every Go app on BTP rebuilds it.

It ships as two packages:

- **`btpingo`** (this module's root) — the framework-neutral core above. It does not import Gin, so a huma (or other non-Gin) service can depend on it alone.
- **`btpingo/ginpingo`** — Gin middleware and handlers built on the core: JWT validation, request ID, `MaxBodySize`, scope enforcement, the error writer, and a generic proxy handler. Import this only from a Gin-based service.

```sh
go get github.com/hochfrequenz/btpingo
```

## Quick start

```go
ctx := context.Background()
env, err := btpingo.LoadEnv() // VCAP_SERVICES: xsuaa, destination, connectivity
if err != nil {
	log.Fatal(err)
}
svc, err := btpingo.NewService(env, btpingo.WithUserAgent("my-service/1.0"))
if err != nil {
	log.Fatal(err)
}
validator, err := btpingo.NewJWTValidator(ctx, env.XSUAA)
if err != nil {
	log.Fatal(err)
}

r := gin.New()
r.Use(ginpingo.RequestID())
api := r.Group("/api", ginpingo.JWT(validator))
api.GET("/ping", func(c *gin.Context) {
	resp, err := svc.CallOnPremise(c.Request.Context(), "MY_SAP_DESTINATION",
		http.MethodGet, "/sap/bc/ping?sap-client=100", nil, nil)
	if err != nil {
		ginpingo.AbortError(c, http.StatusBadGateway, btpingo.CodeUpstreamUnreachable,
			"on-premise system unreachable", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	c.Status(resp.StatusCode)
})
```

Handlers should depend on the `OnPremCaller` (reads) or `OnPremMutator` (writes with CSRF) interface, not on `*Service`. Then a test can pass a one-method fake.

The full API surface is listed in the package documentation: [`btpingo`](https://pkg.go.dev/github.com/hochfrequenz/btpingo), [`btpingo/ginpingo`](https://pkg.go.dev/github.com/hochfrequenz/btpingo/ginpingo).

## Response compression

```go
srv := &http.Server{Handler: btpingo.CompressHandler(router)}
```

`CompressHandler` wraps any `http.Handler` (a `*gin.Engine`, a huma mux, or a plain `http.ServeMux`) with gzip/zstd response compression, negotiated per request via `Accept-Encoding`. It moved here from [go-sap-btp-cf-template](https://github.com/Hochfrequenz/go-sap-btp-cf-template) so every consumer gets one shared, tested copy.

It also closes a Content-Length mismatch gap compression would otherwise introduce: without a guard, a handler that writes fewer or more bytes than its declared `Content-Length` (e.g. a proxied on-prem response whose connection drops mid-copy) would reach the client as a clean, fully-decodable response that is silently short or long, instead of the broken connection an uncompressed response of the same shape would produce. `CompressHandler` detects the mismatch and aborts the connection instead.

## Safety defaults

- **Host pin:** an on-premise request always goes to the destination's own scheme and host. A path suffix, an authenticator or a redirect cannot steer it elsewhere. Redirects are followed only while they stay on that origin.
- **Response size cap:** on-premise response bodies are capped at 10 MiB by default (`WithOnPremResponseSizeLimit`).
- **Caching:** tokens and destination lookups are cached, and concurrent cache misses share a single upstream call.
- **Request IDs:** an inbound `X-Request-Id` is accepted only if it matches `^[A-Za-z0-9._-]{1,64}$`. Otherwise a fresh one is generated.

## Origin and stability

This code started as `internal/btp` in [go-sap-btp-cf-template](https://github.com/Hochfrequenz/go-sap-btp-cf-template). It is being extracted so that fixes reach every service as a dependency bump instead of being copied between forks.

Until `v1.0.0` the API may change between minor versions. A breaking change is always named in the release notes. The gin-specific helpers (`JWT`, `RequestID`, `RequireScope`, `MaxBodySize`, `AbortError`, `ProxyHandler`) have moved into the `ginpingo` subpackage, so that the core can be used without gin.

## License

MIT, see [LICENSE](LICENSE).
