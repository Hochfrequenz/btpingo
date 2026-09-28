// Package btpingo (BTPinGo) is a Go client for the SAP BTP Cloud
// Foundry runtime: XSUAA JWT validation, Destination-service lookup,
// and on-premise calls through the Connectivity proxy / Cloud
// Connector. Around that it provides pluggable destination-level
// authenticators, a typed API error envelope with request-ID
// correlation, and transparent CSRF handshaking for mutating calls.
//
// # API surface
//
// ## Service & on-prem plumbing
//
//   - [Service], [NewService]
//   - [*Service.CallOnPremise], [*Service.CallOnPremiseMutating]
//   - [OnPremCaller]                — interface handlers should depend on for reads
//   - [OnPremMutator]               — interface handlers should depend on for writes (CSRF)
//   - [*Service.ProxyHandler]       — Gin pass-through handler for a generic proxy route
//   - [*Service.Authenticators]     — registry accessor for startup wiring of SSO / PP / …
//   - [NewOnPremiseTransport], [ConnTokenProvider]
//   - [ServiceOption], [WithUserAgent], [WithMgmtTimeout], [WithOnPremiseTimeout],
//     [WithCSRFFetchPath], [WithDestinationCacheTTL], [WithOnPremResponseSizeLimit]
//   - [DefaultOnPremiseTimeout], [DefaultMgmtTimeout], [DefaultUserAgent],
//     [DefaultCSRFFetchPath], [DefaultOnPremResponseSizeLimit]
//
// ## JWT validation & middleware
//
//   - [JWTValidator], [NewJWTValidator]
//   - [*JWTValidator.Middleware], [*JWTValidator.Parse]
//   - [ForwardedUserTokenKey]
//   - [RequestID], [RequestIDFromContext], [ContextWithRequestID], [RequestIDHeader], [RequestIDContextKey]
//   - [RequireScope]
//   - [ContextWithScopes], [ScopesFromContext], [HasScope]  — scope reads for handlers with no Gin context
//   - [MaxBodySize], [DefaultMaxBodyBytes]
//
// ## Error envelope
//
//   - [AbortError]              — the single blessed writer for error responses
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
// ## On-prem failure classification
//
//   - [OnPremFailureKind] — typed classifier; stable wire format
//   - [OnPremFailureDestinationNotFound], [OnPremFailureResponseTooLarge],
//     [OnPremFailureTimeout], [OnPremFailureCanceled], [OnPremFailureTransport]
//   - [ClassifyOnPremError] — (kind, detail) for huma 502 envelopes (err path)
//   - [OnPremNon2xxDetail] — stable detail string for the non-2xx-from-SAP path
package btpingo
