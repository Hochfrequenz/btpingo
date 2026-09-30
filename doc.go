// Package btpingo (BTPinGo) is a Go client for the SAP BTP Cloud
// Foundry runtime: XSUAA JWT validation, Destination-service lookup,
// and on-premise calls through the Connectivity proxy / Cloud
// Connector. Around that it provides pluggable destination-level
// authenticators, a typed API error envelope with request-ID
// correlation, and transparent CSRF handshaking for mutating calls.
//
// This package is framework-neutral and does not import Gin. A
// Gin-based service additionally imports
// github.com/hochfrequenz/btpingo/ginpingo for the Gin middleware and
// handlers (JWT validation, request ID, scope enforcement, the error
// writer, and a generic proxy handler); a huma or other non-Gin
// service uses this package's context helpers directly and never
// needs that subpackage.
//
// # API surface
//
// ## Service & on-prem plumbing
//
//   - [Service], [NewService]
//   - [*Service.CallOnPremise], [*Service.CallOnPremiseMutating]
//   - [OnPremCaller]                — interface handlers should depend on for reads
//   - [OnPremMutator]               — interface handlers should depend on for writes (CSRF)
//   - [*Service.Authenticators]     — registry accessor for startup wiring of SSO / PP / …
//   - [NewOnPremiseTransport], [ConnTokenProvider]
//   - [ServiceOption], [WithUserAgent], [WithMgmtTimeout], [WithOnPremiseTimeout],
//     [WithCSRFFetchPath], [WithDestinationCacheTTL], [WithOnPremResponseSizeLimit]
//   - [DefaultOnPremiseTimeout], [DefaultMgmtTimeout], [DefaultUserAgent],
//     [DefaultCSRFFetchPath], [DefaultOnPremResponseSizeLimit]
//
// ## JWT validation & request-scoped context
//
//   - [JWTValidator], [NewJWTValidator], [*JWTValidator.Parse]
//   - [ForwardedUserTokenKey]
//   - [ScopesFromClaims]            — normalises the "scope" claim for a framework adapter
//   - [RequestIDHeader], [RequestIDFromContext], [ContextWithRequestID]
//   - [ValidRequestID], [NewRequestID] — the request-ID validation and generation a
//     framework adapter's request-ID middleware needs
//   - [ContextWithScopes], [ScopesFromContext], [HasScope]  — scope reads for handlers with no Gin context
//
// ## Error envelope
//
//   - [ErrorEnvelope], [ErrorDetail], [ErrorCode]
//   - [CodeInvalidRequest], [CodeUnauthorized], [CodeForbidden],
//     [CodeNotFound], [CodeMethodNotAllowed], [CodeRequestTooLarge],
//     [CodeUpstreamUnreachable], [CodeInternal]
//
// ## Environment / VCAP bindings
//
//   - [Env], [LoadEnv], [*Env.Validate]
//   - [XSUAACredentials], [DestCredentials], [ConnCredentials]
//   - [Destination], [LookupDestination]
//   - [DestinationCache], [NewDestinationCache], [DefaultDestinationCacheTTL]
//
// ## Authenticator registry
//
//   - [AuthenticatorRegistry], [*AuthenticatorRegistry.Register],
//     [*AuthenticatorRegistry.SetFallback], [*AuthenticatorRegistry.Apply]
//   - [DestinationAuthenticator] interface
//   - [DefaultAuthenticators], [NoAuthenticator], [BasicAuthenticator]
//   - [AuthType], [ProxyType]
//   - [AuthNone], [AuthBasic], [AuthPrincipalPropagation], … and [ProxyOnPremise], [ProxyInternet], [ProxyPrivateLink]
//
// ## Tokens
//
//   - [TokenFetcher], [NewTokenFetcher]
//   - [TokenRefreshLeeway]
//
// ## Sentinel errors
//
//   - [ErrNoDestinationBinding], [ErrNoConnectivityBinding], [ErrNoXSUAABinding]
//   - [ErrDestinationNotFound], [ErrNotInCloudFoundry]
//   - [ErrOnPremResponseTooLarge], [ErrOnPremCrossOriginRedirect]
//
// ## Response compression
//
//   - [CompressHandler] — wraps an http.Handler with gzip/zstd response
//     compression and a Content-Length guard; srv.Handler = CompressHandler(router)
//
// ## On-prem failure classification
//
//   - [OnPremFailureKind] — typed classifier; stable wire format
//   - [OnPremFailureDestinationNotFound], [OnPremFailureResponseTooLarge],
//     [OnPremFailureTimeout], [OnPremFailureCanceled], [OnPremFailureTransport]
//   - [ClassifyOnPremError] — (kind, detail) for huma 502 envelopes (err path)
//   - [OnPremNon2xxDetail] — stable detail string for the non-2xx-from-SAP path
package btpingo
