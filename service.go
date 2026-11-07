package btpingo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hochfrequenz/btpingo/internal/fwdheader"
	"github.com/hochfrequenz/btpingo/internal/limitbody"
	"github.com/hochfrequenz/btpingo/internal/onprem"
	"github.com/hochfrequenz/btpingo/internal/pathsuffix"
)

// OnPremCaller is the single-method contract Gin handlers should depend
// on for read-only on-premise calls. *Service satisfies it in production;
// unit tests substitute a fake with one method to exercise handler logic
// without standing up the XSUAA / Destination / Cloud Connector stack.
//
// Signature mirrors Service.CallOnPremise exactly, so the interface is
// a no-op refactor for existing callers: swap the handler's parameter
// type from *Service to OnPremCaller and every call site keeps compiling.
type OnPremCaller interface {
	CallOnPremise(ctx context.Context, destName, method, pathSuffix string,
		headers http.Header, body io.Reader) (*http.Response, error)
}

// OnPremMutator is the mutating-call contract handlers should depend
// on for writes (POST / PUT / DELETE / PATCH against SAP endpoints
// that enforce CSRF). Implementations perform the X-CSRF-Token
// handshake transparently — callers just invoke
// CallOnPremiseMutating and get a response that already went through
// fetch-token → attach-token-and-cookies → retry-once-on-403.
//
// Handlers that mix reads and writes declare a composite interface
// at the usage site:
//
//	type InvoiceClient interface {
//	    btpingo.OnPremCaller
//	    btpingo.OnPremMutator
//	}
//
// *Service satisfies both so wiring stays unchanged.
type OnPremMutator interface {
	CallOnPremiseMutating(ctx context.Context, destName, method, pathSuffix string,
		headers http.Header, body io.Reader) (*http.Response, error)
}

// Service orchestrates a call to an on-premise SAP system behind the Cloud
// Connector: destination lookup → connectivity token → proxied call with the
// right auth headers. Safe for concurrent use.
//
// Service satisfies the OnPremCaller interface — handlers should accept
// that interface rather than *Service so unit tests can substitute a fake.
type Service struct {
	env                     *Env
	tokens                  *TokenFetcher
	destinations            *DestinationCache
	authenticators          *AuthenticatorRegistry
	mgmtClient              *http.Client
	onPremClient            *http.Client
	userAgent               string
	onPremResponseSizeLimit int64
	noRetry401              bool

	// csrf runs the CSRF handshake of CallOnPremiseMutating.
	csrf *onprem.CSRF
}

// DefaultMgmtTimeout is the per-call timeout for management calls (XSUAA
// token exchange, Destination service lookup). Override with
// WithMgmtTimeout when a specific service needs a different value.
const DefaultMgmtTimeout = 10 * time.Second

// DefaultUserAgent is the User-Agent header sent on outbound on-prem
// requests when no WithUserAgent option is supplied. Services should
// set an explicit UA (e.g. name plus version from
// debug.ReadBuildInfo) so traces on the SAP side can tell callers of
// this library apart.
const DefaultUserAgent = "btpingo"

// DefaultCSRFFetchPath is the SAP path CallOnPremiseMutating calls
// with `X-CSRF-Token: Fetch` to retrieve a token. Defaults to ADT's
// bootstrap endpoint because ADT is the most common target for
// mutating on-prem calls. Override with WithCSRFFetchPath if
// the destination doesn't route /sap/bc/adt/* — a bare GET against
// a REST endpoint on the same ICF node works too.
const DefaultCSRFFetchPath = "/sap/bc/adt/discovery"

// DefaultOnPremResponseSizeLimit caps how much of an on-prem response
// body Service will let a caller read. The Cloud Connector tunnel
// itself is trusted, but a misbehaving SAP backend, a misrouted
// hostname, or — for customer-managed CC topologies — a MITM between
// CC and SAP could otherwise stream gigabytes into the app's 128 MiB
// CF memory quota. 10 MiB is well above any legitimate typed-API
// response (ADT XML, a few hundred KiB of FI line items, etc.).
//
// On overshoot, the wrapped resp.Body returns ErrOnPremResponseTooLarge
// from Read; the caller's io.ReadAll surfaces it and the handler
// translates to btpingo.CodeUpstreamUnreachable (502).
//
// Override with WithOnPremResponseSizeLimit when a specific service
// has a route that legitimately returns more.
const DefaultOnPremResponseSizeLimit int64 = 10 << 20

// ErrOnPremResponseTooLarge is returned by reads on an on-prem response
// body once the per-call cap configured via WithOnPremResponseSizeLimit
// (default DefaultOnPremResponseSizeLimit) is exceeded. Callers using
// io.ReadAll surface this error from their ReadAll call; the typical
// translation in handlers is btpingo.CodeUpstreamUnreachable (502).
var ErrOnPremResponseTooLarge = errors.New("on-prem response exceeds configured size limit")

// ErrOnPremCrossOriginRedirect is returned by CallOnPremise and
// CallOnPremiseMutating when the on-prem system answers with a redirect
// to a different scheme or host than the request it redirects. Such a
// redirect is not followed: CallOnPremise pins the first request to the
// destination's scheme+host, and following a Location elsewhere would
// send the next request — through the Connectivity proxy, with a fresh
// Proxy-Authorization, and for the same hostname on another port or
// scheme also with the destination's Authorization — to a target nobody
// configured. Same-origin
// redirects are still followed. Like any transport error it classifies
// as OnPremFailureTransport.
var ErrOnPremCrossOriginRedirect = errors.New("on-prem redirect to a different scheme or host")

// checkOnPremRedirect is the on-prem client's CheckRedirect, shared with
// btpingotest.HandlerCaller; see onprem.RedirectPolicy.
var checkOnPremRedirect = onprem.RedirectPolicy(ErrOnPremCrossOriginRedirect)

// ServiceOption configures NewService. Use WithUserAgent, WithMgmtTimeout,
// and WithOnPremiseTimeout to tune the defaults; zero options keeps the
// built-in values.
type ServiceOption func(*serviceOptions)

type serviceOptions struct {
	userAgent               string
	mgmtTimeout             time.Duration
	onPremiseTimeout        time.Duration
	csrfFetchPath           string
	onPremResponseSizeLimit int64
	destinationCacheTTL     time.Duration
	noRetry401              bool
}

// WithUserAgent sets the User-Agent header for outbound on-prem requests.
// An empty string resets to DefaultUserAgent.
func WithUserAgent(ua string) ServiceOption {
	return func(o *serviceOptions) { o.userAgent = ua }
}

// WithMgmtTimeout overrides the management-call timeout (XSUAA, Destination
// service lookup). Zero resets to DefaultMgmtTimeout.
func WithMgmtTimeout(d time.Duration) ServiceOption {
	return func(o *serviceOptions) { o.mgmtTimeout = d }
}

// WithOnPremiseTimeout overrides the per-call timeout for on-prem requests.
// Zero resets to DefaultOnPremiseTimeout.
func WithOnPremiseTimeout(d time.Duration) ServiceOption {
	return func(o *serviceOptions) { o.onPremiseTimeout = d }
}

// WithCSRFFetchPath overrides the SAP path CallOnPremiseMutating calls
// to pick up a fresh X-CSRF-Token. Empty string resets to
// DefaultCSRFFetchPath. Change this if your destination doesn't host
// /sap/bc/adt/* — pass the path of any GET-capable SAP endpoint that
// responds to `X-CSRF-Token: Fetch` with a token and a session cookie.
func WithCSRFFetchPath(path string) ServiceOption {
	return func(o *serviceOptions) { o.csrfFetchPath = path }
}

// WithOnPremResponseSizeLimit caps the per-call on-prem response body.
// Reads that would push a single response past `bytes` return
// ErrOnPremResponseTooLarge from the wrapped resp.Body. Zero or
// negative resets to DefaultOnPremResponseSizeLimit — a negative limit
// has no sensible meaning as a cap, and limitbody's slice math
// assumes a non-negative one. Pass a larger value if a single route
// legitimately returns more.
func WithOnPremResponseSizeLimit(bytes int64) ServiceOption {
	return func(o *serviceOptions) { o.onPremResponseSizeLimit = bytes }
}

// WithDestinationCacheTTL overrides how long a looked-up destination is
// reused before CallOnPremise asks the Destination service again.
// Zero or negative resets to DefaultDestinationCacheTTL.
func WithDestinationCacheTTL(d time.Duration) ServiceOption {
	return func(o *serviceOptions) { o.destinationCacheTTL = d }
}

// WithRetry401 controls the one replay of a body-less call after a 401.
// The default is true: CallOnPremise drops the cached connectivity token
// and destination and repeats the call once. Pass false to return the
// first 401 as-is (the caches are still dropped, so the next call looks
// both up fresh). Use false when a replay is costly, e.g. a wrong
// destination password would otherwise cost two failed logons per call
// and risk locking the SAP user. Body-carrying calls are never replayed.
func WithRetry401(retry bool) ServiceOption {
	return func(o *serviceOptions) { o.noRetry401 = !retry }
}

// NewService wires a Service using the defaults listed in DefaultMgmtTimeout,
// DefaultOnPremiseTimeout, and DefaultUserAgent, plus DefaultAuthenticators()
// and a TokenFetcher with its own http.Client. Pass ServiceOptions to tune
// timeouts or the outbound User-Agent.
func NewService(env *Env, opts ...ServiceOption) (*Service, error) {
	if env == nil {
		return nil, errors.New("nil env")
	}
	if env.Dest == nil {
		return nil, ErrNoDestinationBinding
	}
	if env.Conn == nil {
		return nil, ErrNoConnectivityBinding
	}

	o := serviceOptions{
		userAgent:               DefaultUserAgent,
		mgmtTimeout:             DefaultMgmtTimeout,
		onPremiseTimeout:        DefaultOnPremiseTimeout,
		csrfFetchPath:           DefaultCSRFFetchPath,
		onPremResponseSizeLimit: DefaultOnPremResponseSizeLimit,
	}
	for _, opt := range opts {
		opt(&o)
	}
	// Treat zero/empty field values as "use the default" so callers can
	// compose a struct of options without knowing which fields they care
	// about — e.g. WithMgmtTimeout(0) falls back to the constant.
	if o.userAgent == "" {
		o.userAgent = DefaultUserAgent
	}
	if o.mgmtTimeout == 0 {
		o.mgmtTimeout = DefaultMgmtTimeout
	}
	if o.onPremiseTimeout == 0 {
		o.onPremiseTimeout = DefaultOnPremiseTimeout
	}
	if o.csrfFetchPath == "" {
		o.csrfFetchPath = DefaultCSRFFetchPath
	}
	if o.onPremResponseSizeLimit <= 0 {
		o.onPremResponseSizeLimit = DefaultOnPremResponseSizeLimit
	}

	tokens := NewTokenFetcher(nil)

	transport, err := NewOnPremiseTransport(env.Conn, func(req *http.Request) (string, error) {
		return tokens.Fetch(req.Context(), env.Conn.URL, env.Conn.ClientID, env.Conn.ClientSecret)
	})
	if err != nil {
		return nil, fmt.Errorf("on-premise transport: %w", err)
	}

	// The management client (XSUAA, Destination service) and the on-prem
	// client must be distinct: the on-prem one has a RoundTripper that
	// routes through the Connectivity proxy. Re-using it for management
	// calls would tunnel XSUAA token requests through the reverse proxy.
	mgmtClient := &http.Client{Timeout: o.mgmtTimeout}

	return &Service{
		env:                     env,
		tokens:                  tokens,
		destinations:            NewDestinationCache(mgmtClient, o.destinationCacheTTL),
		authenticators:          DefaultAuthenticators(),
		mgmtClient:              mgmtClient,
		onPremClient:            &http.Client{Transport: transport, Timeout: o.onPremiseTimeout, CheckRedirect: checkOnPremRedirect},
		userAgent:               o.userAgent,
		onPremResponseSizeLimit: o.onPremResponseSizeLimit,
		noRetry401:              o.noRetry401,
		csrf:                    onprem.NewCSRF(o.csrfFetchPath),
	}, nil
}

// Authenticators exposes the registry so callers can plug in Auth0 / SSO /
// PrincipalPropagation handlers at startup.
func (s *Service) Authenticators() *AuthenticatorRegistry { return s.authenticators }

// CallOnPremise runs the three-leg sequence for destination `destName` and
// forwards `method path` (path is appended to the destination's URL). The
// destination token fetch and the destination lookup itself are both
// cached (DefaultDestinationCacheTTL for the latter), so a call does
// not pay a full Destination-service round trip every time. On EVERY
// 401 the connectivity token is invalidated and the cached destination
// is dropped — bearer tokens can expire between cache check and
// on-prem receipt, and a destination's own credentials (e.g. a
// BasicAuthentication password) can be rotated in the cockpit, so
// neither stale value should keep being served. The call itself is
// retried only when body is nil: a body-carrying call's io.Reader is
// already consumed by the failed attempt and cannot be safely
// re-sent, so it returns the 401 as-is: but because the caches were
// already dropped, the next call on this destination looks both up
// fresh and heals itself. 403 is NOT retried and does NOT invalidate
// either cache: it means "authenticated but not authorized", which a
// fresh token cannot fix and re-trying would mask real
// auth-policy bugs.
// WithRetry401(false) switches that single replay off. Use Origin401 on
// a 401 response to tell the connectivity proxy's rejection from the
// on-prem system's.
// The returned response body must be closed by the caller.
//
// The returned resp.Body is capped at DefaultOnPremResponseSizeLimit
// (override via WithOnPremResponseSizeLimit). A read past the cap
// returns ErrOnPremResponseTooLarge; an io.ReadAll caller sees that
// error from the call and should surface it as 502
// (CodeUpstreamUnreachable). The cap protects against an SAP/CC
// misroute streaming gigabytes into the CF memory quota.
func (s *Service) CallOnPremise(ctx context.Context, destName, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error) {
	if err := pathsuffix.Check(pathSuffix); err != nil {
		return nil, err
	}

	destToken, err := s.tokens.Fetch(ctx, s.env.Dest.URL, s.env.Dest.ClientID, s.env.Dest.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("destination token: %w", err)
	}
	dest, err := s.destinations.Lookup(ctx, s.env.Dest, destToken, destName)
	if err != nil {
		return nil, fmt.Errorf("destination lookup: %w", err)
	}

	resp, err := s.callOnce(ctx, dest, method, pathSuffix, headers, body)
	if err != nil {
		return nil, err
	}
	// A 401 means the connectivity token, the destination's own
	// credentials, or both are stale — e.g. a BasicAuthentication
	// password rotated in the cockpit — and the cached entries would
	// otherwise keep serving the stale values for up to their
	// respective TTLs. Drop both on every 401, regardless of whether
	// this call can retry, so at least the NEXT call on this
	// destination starts from a clean cache.
	if resp.StatusCode == http.StatusUnauthorized {
		s.invalidateOn401(destName)
	}
	// Body may be read-once (io.Reader), so we only retry when the caller
	// handed us nil — safer than silently draining and re-seeking. A
	// body-carrying call that gets a 401 returns it as-is; the cache
	// invalidation above still lets the next call heal itself.
	if !s.noRetry401 && onprem.Retry401(resp.StatusCode, body) {
		_ = resp.Body.Close()
		dest, err = s.destinations.Lookup(ctx, s.env.Dest, destToken, destName)
		if err != nil {
			return nil, fmt.Errorf("destination lookup: %w", err)
		}
		resp, err = s.callOnce(ctx, dest, method, pathSuffix, headers, nil)
		// The retry's lookup refilled both caches. If the retry is
		// rejected too, those values are known bad: drop them again so
		// they are not served to the next call. No further retry.
		if err == nil && resp.StatusCode == http.StatusUnauthorized {
			s.invalidateOn401(destName)
		}
	}
	return resp, err
}

// invalidateOn401 drops the cached Connectivity token and the cached
// destination after an on-prem 401, so the next attempt fetches both
// fresh.
func (s *Service) invalidateOn401(destName string) {
	s.tokens.Invalidate(s.env.Conn.URL, s.env.Conn.ClientID)
	s.destinations.Invalidate(s.env.Dest, destName)
}

// CallOnPremiseMutating is the write counterpart of CallOnPremise.
// SAP ICF endpoints that accept POST / PUT / DELETE / PATCH typically
// require a CSRF token in `X-CSRF-Token`, together with the SAP
// session cookies set by the server when the token was first minted.
// This method runs that handshake for you:
//
//  1. Look up the token + cookies for `destName` in the Service's
//     CSRF cache; on a miss, GET the configured CSRF fetch path
//     (WithCSRFFetchPath, default DefaultCSRFFetchPath) with
//     `X-CSRF-Token: Fetch` and cache what comes back.
//  2. Attach the cached token and cookies to the mutating call and
//     send it.
//  3. On a 403 carrying `X-CSRF-Token: Required` (SAP's signal that
//     the server-side session was recycled), invalidate the cache,
//     re-fetch once, and retry the mutating call a single time.
//
// The request body is buffered up-front so the retry can re-read it.
// If your body is too large to buffer, write your own handshake on
// top of CallOnPremise rather than using this helper.
//
// Returns the final response (body must be closed by the caller) or
// the underlying error. A 403 that is NOT a CSRF-required signal
// (i.e. a real authorization failure) surfaces to the caller as-is,
// no retry.
//
// As with CallOnPremise, resp.Body is capped at
// DefaultOnPremResponseSizeLimit (override via WithOnPremResponseSizeLimit);
// a read past the cap returns ErrOnPremResponseTooLarge.
func (s *Service) CallOnPremiseMutating(ctx context.Context, destName, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error) {
	return s.csrf.Do(ctx, s.CallOnPremise, destName, method, pathSuffix, headers, body)
}

func (s *Service) callOnce(ctx context.Context, dest *Destination, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error) {
	// Parse the destination base URL up front so we can pin the request's
	// scheme+host below. dest.URL comes from the SAP Destination service
	// (operator-configured, trusted); pathSuffix is user-influenced and
	// only sanitised for traversal/encoding in CallOnPremise. Pinning the
	// host here closes the remaining server-side-request-forgery gap: even
	// if a future caller forwards a crafted suffix, the request can never
	// be steered to a different scheme or host than the configured
	// destination.
	base, err := url.Parse(trimSlash(dest.URL))
	if err != nil {
		return nil, fmt.Errorf("parse destination url %q: %w", dest.URL, err)
	}
	target := base.String()
	if pathSuffix != "" {
		if !strings.HasPrefix(pathSuffix, "/") {
			pathSuffix = "/" + pathSuffix
		}
		target += pathSuffix
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("build on-prem request: %w", err)
	}
	// SSRF guard: the user-influenced pathSuffix must not be able to
	// redirect the call away from the destination's own scheme+host.
	if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host {
		return nil, fmt.Errorf("on-prem request target %q does not match destination host %s://%s", target, base.Scheme, base.Host)
	}
	fwdheader.Forward(req.Header, headers)
	// A neutral, self-identifying UA. Impersonating a browser to get past
	// a system-specific SAP filter is not a BTP requirement and is not
	// done here. The concrete value comes from WithUserAgent (or
	// DefaultUserAgent) — services should pass WithUserAgent so
	// SAP-side traces distinguish the caller.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", s.userAgent)
	}
	// Multi-CC routing header: only set when the destination carries a
	// LocationId. Setting it otherwise can make the Connectivity service
	// reject the call with "unknown location".
	if dest.CloudConnectorLocationID != "" {
		req.Header.Set("SAP-Connectivity-SCC-Location_ID", dest.CloudConnectorLocationID)
	}

	if err := s.authenticators.Apply(ctx, req, dest); err != nil {
		return nil, fmt.Errorf("apply destination auth: %w", err)
	}
	// Re-check the pin: an authenticator receives the mutable request
	// (DestinationAuthenticator is a public extension point), so a custom
	// one could otherwise steer it to another scheme or host.
	if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host {
		return nil, fmt.Errorf("destination authenticator changed the on-prem request target to %s://%s; destination host is %s://%s",
			req.URL.Scheme, req.URL.Host, base.Scheme, base.Host)
	}
	resp, err := s.onPremClient.Do(req)
	if err != nil {
		return nil, err
	}
	// Cap the readable body so a misbehaving SAP / misrouted endpoint /
	// MITM in a customer-managed CC topology cannot stream gigabytes
	// into the app's 128 MiB CF memory quota. The wrap is transparent
	// to honest callers — io.ReadAll on a small response works as
	// before; an attempt to read past the cap returns
	// ErrOnPremResponseTooLarge from Read, which the caller's io.ReadAll
	// surfaces as a typed error.
	resp.Body = limitbody.New(resp.Body, s.onPremResponseSizeLimit, ErrOnPremResponseTooLarge)
	return resp, nil
}

// filterForwardedCookies keeps only the SAP session cookies of one
// inbound Cookie header value; see fwdheader.FilterCookies.
func filterForwardedCookies(cookieHeader string) string {
	return fwdheader.FilterCookies(cookieHeader)
}
