package btpingo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// AuthType enumerates the values SAP BTP puts in a destination's
// Authentication property. A typed alias keeps the authenticator registry
// compile-safe — a typo in a constant fails to build instead of silently
// falling through to the reject-fallback at runtime.
type AuthType string

const (
	AuthNone                    AuthType = "NoAuthentication"
	AuthBasic                   AuthType = "BasicAuthentication"
	AuthOAuth2ClientCredentials AuthType = "OAuth2ClientCredentials"
	AuthOAuth2UserTokenExchange AuthType = "OAuth2UserTokenExchange"
	AuthOAuth2JWTBearer         AuthType = "OAuth2JWTBearer"
	AuthOAuth2SAMLBearer        AuthType = "OAuth2SAMLBearerAssertion"
	AuthPrincipalPropagation    AuthType = "PrincipalPropagation"
	AuthSAMLAssertion           AuthType = "SamlAssertion"
	AuthClientCertificate       AuthType = "ClientCertificateAuthentication"
)

// ProxyType enumerates SAP BTP destination proxy modes. Only OnPremise
// traffic must route through the Connectivity service's reverse proxy; for
// Internet and PrivateLink the transport is a plain outbound call. The
// Service uses this to decide whether the Connectivity binding must be
// present at all.
type ProxyType string

const (
	ProxyOnPremise   ProxyType = "OnPremise"
	ProxyInternet    ProxyType = "Internet"
	ProxyPrivateLink ProxyType = "PrivateLink"
)

// ErrDestinationNotFound wraps a 404 from the Destination service so callers
// can branch on it via errors.Is. Any other 4xx/5xx returns a plain error.
var ErrDestinationNotFound = errors.New("destination not found")

// Destination is the subset of a Destination-service record this library
// reads. Additional Destination-service properties (sap-client, WebIDEUsage,
// etc.) are intentionally dropped: callers that need them can re-fetch the
// raw JSON or extend this struct.
type Destination struct {
	Name                     string    `json:"Name"`
	Type                     string    `json:"Type"`
	URL                      string    `json:"URL"`
	Authentication           AuthType  `json:"Authentication"`
	ProxyType                ProxyType `json:"ProxyType"`
	User                     string    `json:"User,omitempty"`
	Password                 string    `json:"Password,omitempty"`
	CloudConnectorLocationID string    `json:"CloudConnectorLocationId,omitempty"`
}

// IsOnPremise reports whether the destination targets a system reachable
// only via the Connectivity service's reverse proxy.
func (d *Destination) IsOnPremise() bool {
	return d.ProxyType == ProxyOnPremise
}

// String masks Password so accidental %v / %+v logging cannot leak it.
// Mirrors the precedent set by *Credentials in env.go.
func (d *Destination) String() string {
	if d == nil {
		return "<nil destination>"
	}
	return fmt.Sprintf(
		"Destination{Name:%s Type:%s URL:%s Authentication:%s ProxyType:%s User:%s Password:*** CloudConnectorLocationId:%s}",
		d.Name, d.Type, d.URL, d.Authentication, d.ProxyType, d.User, d.CloudConnectorLocationID)
}

// Format routes %v/%+v/%#v through String() so password scrubbing survives
// every formatter that callers might reach for in a log line.
func (d *Destination) Format(s fmt.State, _ rune) { _, _ = fmt.Fprint(s, d.String()) }

// destinationEnvelope matches the /destination-configuration/v1 response.
// The service wraps the destination in `destinationConfiguration` and adds
// siblings like `authTokens` we do not use here.
type destinationEnvelope struct {
	DestinationConfiguration Destination `json:"destinationConfiguration"`
}

// LookupDestination fetches a destination by name from the Destination
// service. It calls the generic /destinations/{name} endpoint, which searches
// instance- and subaccount-scope and is recommended by SAP over the
// scope-specific variants (`/instanceDestinations/`, `/subaccountDestinations/`).
func LookupDestination(ctx context.Context, httpClient *http.Client, cred *DestCredentials, bearer, name string) (*Destination, error) {
	if cred == nil {
		return nil, ErrNoDestinationBinding
	}
	if name == "" {
		return nil, errors.New("destination name is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	endpoint := fmt.Sprintf("%s/destination-configuration/v1/destinations/%s",
		trimSlash(cred.URI), url.PathEscape(name))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build destination request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("destination lookup: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the body read: the Destination service is trusted but a misrouted
	// response (proxy, DNS, etc.) could otherwise balloon memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMgmtResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read destination response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %q", ErrDestinationNotFound, name)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("destination service returned %d for %q", resp.StatusCode, name)
	}

	// The envelope shape is documented; we also accept the direct shape
	// because older service surfaces and test fixtures sometimes return it.
	var env destinationEnvelope
	if err := json.Unmarshal(body, &env); err == nil && env.DestinationConfiguration.URL != "" {
		return &env.DestinationConfiguration, nil
	}
	var direct Destination
	if err := json.Unmarshal(body, &direct); err == nil && direct.URL != "" {
		return &direct, nil
	}
	return nil, fmt.Errorf("destination %q response did not contain a URL", name)
}

// maxMgmtResponseBytes caps the body read from XSUAA and the Destination
// service. 1 MiB is well above any legitimate response these services send.
const maxMgmtResponseBytes = 1 << 20

// DefaultDestinationCacheTTL bounds how long a looked-up destination is
// reused before [DestinationCache] asks the Destination service again.
// Destinations are operator-configured and change rarely, so this is
// generous compared to a token TTL — but it is finite rather than
// "cache forever", so a destination fixed in the cockpit after a
// misconfiguration heals here within one TTL rather than requiring an
// app restart.
const DefaultDestinationCacheTTL = 5 * time.Minute

type cachedDestination struct {
	dest      *Destination
	expiresAt time.Time
}

// DestinationCache wraps [LookupDestination] with the same caching
// shape [TokenFetcher] already gives the token fetch it runs beside on
// every on-premise call. Without it, the destination lookup would be
// the one leg of that three-leg sequence — token, destination, proxied
// call — with no cache at all, so every call would pay a full
// Destination-service round trip, and a burst of concurrent requests
// during a cold cache would become a burst of concurrent
// Destination-service calls. One instance is safe for concurrent use.
type DestinationCache struct {
	httpClient *http.Client
	ttl        time.Duration
	group      singleflight.Group

	mu    sync.Mutex
	cache map[string]cachedDestination
}

// NewDestinationCache returns a cache that looks up destinations via
// httpClient (nil selects a 10s-timeout default, matching
// [LookupDestination]'s own fallback) and reuses each one for ttl
// (zero or negative selects [DefaultDestinationCacheTTL]).
func NewDestinationCache(httpClient *http.Client, ttl time.Duration) *DestinationCache {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl <= 0 {
		ttl = DefaultDestinationCacheTTL
	}
	return &DestinationCache{
		httpClient: httpClient,
		ttl:        ttl,
		cache:      map[string]cachedDestination{},
	}
}

// Lookup returns a cached destination if one is still fresh, else
// performs a fresh [LookupDestination] call. The cache key is
// (cred.URI, cred.URL, cred.ClientID, name) — deliberately not bearer,
// because the destination's own content does not depend on which valid
// token was used to ask for it, and keying on a token that itself
// rotates would defeat the cache on every token refresh.
//
// Keying by binding identity (URI, URL and ClientID) rather than URI
// alone keeps this safe when one *DestinationCache is shared across
// multiple *DestCredentials on a regional Destination-service endpoint
// that hands out the same URI to every caller: ClientID separates
// bindings, and URL separates subscriber tenants of one binding — they
// share a ClientID but get a tenant-subdomain token URL of their own,
// the same distinction [TokenFetcher] keys on.
//
// Concurrent misses for the same key collapse into one upstream call
// via singleflight, for the same reason [TokenFetcher.Fetch] does:
// otherwise a burst of incoming requests hitting a cold cache would
// each dial the Destination service instead of one dialing it and the
// rest waiting on that one result.
func (c *DestinationCache) Lookup(ctx context.Context, cred *DestCredentials, bearer, name string) (*Destination, error) {
	if cred == nil {
		return nil, ErrNoDestinationBinding
	}
	key := cacheKey(cred, name)

	c.mu.Lock()
	d, ok := c.cache[key]
	c.mu.Unlock()
	if ok && time.Now().Before(d.expiresAt) {
		return d.dest, nil
	}

	v, err, _ := c.group.Do(key, func() (any, error) {
		// A second cache read inside the critical section catches the
		// case where a peer finished the lookup while we were waiting.
		c.mu.Lock()
		d, ok := c.cache[key]
		c.mu.Unlock()
		if ok && time.Now().Before(d.expiresAt) {
			return d.dest, nil
		}
		dest, err := LookupDestination(ctx, c.httpClient, cred, bearer, name)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.cache[key] = cachedDestination{dest: dest, expiresAt: time.Now().Add(c.ttl)}
		c.mu.Unlock()
		return dest, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Destination), nil
}

// Invalidate drops the cached destination for (cred.URI, cred.URL,
// cred.ClientID, name). Call this if a destination lookup's result
// turns out to be stale in a way the TTL alone would not catch quickly
// enough — mirrors [TokenFetcher.Invalidate]'s reason for existing.
// Service.CallOnPremise calls it on a 401 so a rotated destination
// credential (e.g. a BasicAuthentication password) is looked up fresh
// on the retry instead of serving the stale entry for up to the cache's
// TTL.
func (c *DestinationCache) Invalidate(cred *DestCredentials, name string) {
	if cred == nil {
		return
	}
	c.mu.Lock()
	delete(c.cache, cacheKey(cred, name))
	c.mu.Unlock()
}

// cacheKey builds the DestinationCache key from (URI, URL, ClientID, name),
// mirroring [TokenFetcher]'s own (URL, ClientID) identity: ClientID
// separates one binding from another, and URL separates subscriber
// tenants of one binding, which share a ClientID but get a
// tenant-subdomain token URL of their own.
//
// Each component is length-prefixed rather than joined with a plain "|"
// separator: a "|" occurring inside a URI, URL or ClientID value would
// otherwise let two distinct (URI, URL, ClientID, name) tuples produce
// the same string, colliding two unrelated cache entries.
func cacheKey(cred *DestCredentials, name string) string {
	var b strings.Builder
	for _, part := range [...]string{cred.URI, cred.URL, cred.ClientID, name} {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return b.String()
}
