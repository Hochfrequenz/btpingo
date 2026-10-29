# BTPinGo 🐧

![Unittests](https://github.com/hochfrequenz/btpingo/actions/workflows/test.yml/badge.svg)
![coverage](https://github.com/hochfrequenz/btpingo/actions/workflows/coverage.yml/badge.svg)
![golangci-lint](https://github.com/hochfrequenz/btpingo/actions/workflows/golangci-lint.yml/badge.svg)

A Go client for apps on **SAP BTP Cloud Foundry** that call an **on-premise SAP system**. It covers:

- **XSUAA:** it validates the JWTs your app receives.
- **Destination service:** it looks up the destination by name.
- **Connectivity service and Cloud Connector:** it fetches the Destination-service and Connectivity tokens a call needs and routes the call through the Connectivity proxy. It handles the CSRF handshake for mutating calls and the destination's own authentication.

SAP's Cloud SDK covers this for Java and JavaScript only. Without it, every Go app on BTP rebuilds it.

It ships as three packages:

- **`btpingo`** (this module's root) — the framework-neutral core above. It does not import Gin, so a huma (or other non-Gin) service can depend on it alone.
- **`btpingo/ginpingo`** — Gin middleware and handlers built on the core: JWT validation, request ID, `MaxBodySize`, `BindStrictJSON`, scope enforcement, the error writer, and a generic proxy handler. Import this only from a Gin-based service.
- **`btpingo/grpcpingo`** — the same for gRPC: `net/http` middleware for [connect-go](https://connectrpc.com/) handlers (JWT and scope check, request-size limit, error mapping with `ErrorInfo`). It serves gRPC, gRPC-Web and Connect. Import this only from a service with connect-go handlers.

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

The full API surface is listed in the package documentation: [`btpingo`](https://pkg.go.dev/github.com/hochfrequenz/btpingo), [`btpingo/ginpingo`](https://pkg.go.dev/github.com/hochfrequenz/btpingo/ginpingo), [`btpingo/grpcpingo`](https://pkg.go.dev/github.com/hochfrequenz/btpingo/grpcpingo).

## ginpingo

`BindStrictJSON(c, &dst, opts...)` decodes exactly one JSON value, allowing only whitespace after it. It returns `false` after calling `AbortError` on failure, so handlers should return immediately:

```go
var input struct {
	Name string `json:"name"`
}
if !ginpingo.BindStrictJSON(c, &input,
	ginpingo.WithMaxBytes(64<<10),
	ginpingo.WithDisallowUnknownFields(),
) {
	return
}
```

The default limit is `DefaultMaxBodyBytes` (1 MiB); `WithMaxBytes` sets a per-call limit without overriding a smaller `MaxBodySize` middleware limit. Overflow yields 413 `CodeRequestTooLarge`. Empty, malformed, type-mismatched, or trailing JSON yields 400 `CodeInvalidRequest`; `WithDisallowUnknownFields` also rejects unknown struct fields. Client messages are stable and generic; underlying errors are logged server-side via `AbortError`. Binding-tag validation is not performed.

## grpcpingo (gRPC / Connect)

`grpcpingo` guards [connect-go](https://connectrpc.com/) handlers, which serve gRPC, gRPC-Web and Connect from one `http.Handler`. Its middleware have the plain `func(http.Handler) http.Handler` shape, so they wrap a handler directly or sit in a gin route through `gin.WrapH`. A rejected call is answered in the protocol of the request, and on a streaming call the status arrives on the stream. The package imports connect-go and `connectrpc.com/authn`; the root package and `ginpingo` do not.

```go
m := grpcpingo.Mapper{Domain: "myservice.example.com"} // ErrorInfo domain, required
path, h := testv1connect.NewTestServiceHandler(impl,
	connect.WithRecover(m.Recover),  // a panic becomes Internal with ErrorInfo
	connect.WithReadMaxBytes(1<<20), // limit for bodies without a Content-Length
)
guard := func(next http.Handler) http.Handler {
	return grpcpingo.Auth(validator, "myapp!t1.User", m)(grpcpingo.MaxBodySize(1<<20, m)(next))
}
r.POST(path+"*rpc", gin.WrapH(guard(h)))

srv := &http.Server{Handler: btpingo.CompressHandlerSkipping(r, path)}
```

- **`Auth(validator, scope, m)`** is `ginpingo.JWT` plus `RequireScope` for connect: `Authorization: Bearer` is required, the token is validated, `scope` must be in it. The context carries the forwarded token and the scopes as with `ginpingo.JWT`, and `WithContextFromClaims` adds more values from the claims. A missing or invalid token is `Unauthenticated` (reason `unauthorized`), a missing scope `PermissionDenied` (`forbidden`). Only an invalid token is logged, once at ERROR, as with `AbortError`. An empty scope panics at construction.
- **`MaxBodySize(limit, m)`** answers a `Content-Length` over `limit` with `ResourceExhausted` (`request_too_large`) and caps every body at `limit` bytes. Put `Auth` before it. A body without a `Content-Length` is caught by `connect.WithReadMaxBytes`, which gives the same code but no `ErrorInfo`, so set both. `Auth` and `MaxBodySize` panic at construction when `Mapper.Domain` is empty.
- **`Mapper`** maps a `btpingo.ErrorCode` to a gRPC code and exactly one `google.rpc.ErrorInfo` whose reason is the code and whose domain is `Mapper.Domain`. `DefaultCodes()` holds the mapping of the canonical codes; pass a changed copy as `Mapper.Codes` to add your own codes. An unknown code becomes `Internal`. `m.Recover` is the `connect.WithRecover` handler: it logs the panic and stack once and returns `Internal` with `ErrorInfo`.
- **`CompressHandlerSkipping(h, prefixes...)`** is `CompressHandler` except that paths under the prefixes go to `h` directly. A prefix should end with `/`, as connect-go's generated path does; an empty prefix panics. Use it for the RPC path: gzhttp would add an HTTP `Content-Encoding` to `application/grpc` responses, and gRPC clients reject that. gRPC and Connect compress messages on their own.

The example routes POST only. A service that enables Connect GET (`connect.WithIdempotency` plus `connect.WithHTTPGet`) must register GET for its path as well, and `MaxBodySize` does not limit the message a GET carries in its query string.

An access log in front of a gRPC service shows HTTP 200 for a failed call: the gRPC status travels in the trailers. Log the gRPC code if you want it in the access log.

## Response compression

```go
srv := &http.Server{Handler: btpingo.CompressHandler(router)}
```

`CompressHandler` wraps any `http.Handler` with response compression. A response is compressed with zstd or gzip only when the request's `Accept-Encoding` accepts one of them by q-value (zstd preferred on a tie); a request with no `Accept-Encoding`, one that excludes both, or a body under the minimum size is sent uncompressed. If a handler writes fewer or more bytes than its declared `Content-Length` (e.g. a proxied on-prem response cut off mid-copy), it aborts the connection instead of sending a cleanly compressed short or long body.

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
