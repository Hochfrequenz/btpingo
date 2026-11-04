// Package onprem holds the call-path logic that btpingo.Service and
// btpingotest.HandlerCaller must share so the fake cannot drift from the
// real thing: the redirect policy, the 401 retry decision and the CSRF
// handshake. It is internal; sentinel errors belong to package btpingo
// and are handed in by the caller.
package onprem

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"
)

// MaxRedirects matches net/http's default redirect limit, which a
// custom CheckRedirect replaces and must therefore re-implement.
const MaxRedirects = 10

// RedirectPolicy returns the on-prem client's CheckRedirect: follow a
// redirect only while it stays on the scheme+host of the original
// request (via[0]), up to MaxRedirects hops. Hosts compare
// case-insensitively; an explicit default port still counts as a
// different host (fail closed). errCrossOrigin is wrapped for a
// cross-origin redirect.
func RedirectPolicy(errCrossOrigin error) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		// Origin first, so a cross-origin redirect reports the sentinel even
		// when it is also the hop that reaches the limit.
		origin := via[0].URL
		if req.URL.Scheme != origin.Scheme || !strings.EqualFold(req.URL.Host, origin.Host) {
			return fmt.Errorf("%w: %s://%s redirected to %s://%s",
				errCrossOrigin, origin.Scheme, origin.Host, req.URL.Scheme, req.URL.Host)
		}
		if len(via) >= MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", MaxRedirects)
		}
		return nil
	}
}

// Retry401 reports whether a call that was answered with status should
// be repeated once: only on 401, and only when the caller handed over no
// body. A body is a read-once io.Reader the failed attempt already
// consumed; it is not drained and re-sent.
func Retry401(status int, body io.Reader) bool {
	return status == http.StatusUnauthorized && body == nil
}

// CallFunc is one on-prem call, as btpingo.OnPremCaller.CallOnPremise.
type CallFunc func(ctx context.Context, destName, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error)

type csrfState struct {
	token   string
	cookies []*http.Cookie
}

// CSRF runs the X-CSRF-Token handshake of btpingo.Service.CallOnPremiseMutating
// on top of any CallFunc. It caches token and SAP session cookies per
// destination; concurrent cold fetches for one destination share a
// single call. Safe for concurrent use.
type CSRF struct {
	fetchPath string
	mu        sync.Mutex
	states    map[string]*csrfState
	group     singleflight.Group
}

// NewCSRF returns a CSRF engine that fetches tokens with GET fetchPath.
func NewCSRF(fetchPath string) *CSRF {
	return &CSRF{fetchPath: fetchPath, states: map[string]*csrfState{}}
}

// Do performs a mutating call through call:
//
//  1. Look up the token + cookies for destName; on a miss, GET the fetch
//     path with `X-CSRF-Token: Fetch` and cache what comes back.
//  2. Attach the cached token and cookies to the call and send it.
//  3. On a 403 carrying `X-CSRF-Token: Required` (SAP's signal that the
//     server-side session was recycled), invalidate, re-fetch once and
//     retry the call a single time.
//
// The request body is buffered up-front so the retry can re-read it.
// A 403 that is not a CSRF-required signal surfaces as-is, no retry.
func (c *CSRF) Do(ctx context.Context, call CallFunc, destName, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("read mutating body: %w", err)
		}
	}

	state, err := c.stateFor(ctx, call, destName)
	if err != nil {
		return nil, err
	}
	resp, err := c.callOnce(ctx, call, destName, method, pathSuffix, headers, bodyBytes, state)
	if err != nil {
		return nil, err
	}
	// SAP signals a CSRF-specific rejection via 403 + X-CSRF-Token: Required.
	// Other 403s are real authz failures and must NOT be retried — they
	// indicate the technical user lacks the object-level authorization,
	// which fresh tokens cannot fix.
	if resp.StatusCode == http.StatusForbidden &&
		strings.EqualFold(resp.Header.Get("X-CSRF-Token"), "Required") {
		_ = resp.Body.Close()
		c.invalidate(destName)
		state, err = c.stateFor(ctx, call, destName)
		if err != nil {
			return nil, err
		}
		resp, err = c.callOnce(ctx, call, destName, method, pathSuffix, headers, bodyBytes, state)
	}
	return resp, err
}

// callOnce attaches the given CSRF token + cookies to a copy of headers
// and delegates to call, so all the plumbing of the read path (lookup,
// 401 retry, authenticators) stays in one place.
func (c *CSRF) callOnce(ctx context.Context, call CallFunc, destName, method, pathSuffix string,
	headers http.Header, body []byte, state *csrfState) (*http.Response, error) {
	out := http.Header{}
	for k, vs := range headers {
		for _, v := range vs {
			out.Add(k, v)
		}
	}
	out.Set("X-CSRF-Token", state.token)
	// RFC 6265 says clients send one Cookie header with cookies joined
	// by "; ". Go lets you Add multiple Cookie headers and the stdlib
	// will send them all, but servers reading via r.Header.Get("Cookie")
	// only see the first value — combine them upfront to avoid that
	// foot-gun on the SAP side.
	if len(state.cookies) > 0 {
		parts := make([]string, 0, len(state.cookies))
		for _, ck := range state.cookies {
			parts = append(parts, ck.Name+"="+ck.Value)
		}
		out.Set("Cookie", strings.Join(parts, "; "))
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	return call(ctx, destName, method, pathSuffix, out, r)
}

// stateFor returns the cached state for destName, fetching it if absent.
// Concurrent first-misses for the same destination are deduped through
// singleflight; the short mutex sections only guard the map and are
// never held across the network call.
func (c *CSRF) stateFor(ctx context.Context, call CallFunc, destName string) (*csrfState, error) {
	c.mu.Lock()
	state, ok := c.states[destName]
	c.mu.Unlock()
	if ok {
		return state, nil
	}
	v, err, _ := c.group.Do(destName, func() (any, error) {
		// Another goroutine's Do() may have populated the cache by
		// the time this callback runs — re-check.
		c.mu.Lock()
		if existing, ok := c.states[destName]; ok {
			c.mu.Unlock()
			return existing, nil
		}
		c.mu.Unlock()

		fetched, err := c.fetch(ctx, call, destName)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.states[destName] = fetched
		c.mu.Unlock()
		return fetched, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*csrfState), nil
}

// fetch performs the X-CSRF-Token: Fetch handshake against the fetch path.
func (c *CSRF) fetch(ctx context.Context, call CallFunc, destName string) (*csrfState, error) {
	// Accept: */* matters — some SAP ICF nodes return 400 without it
	// on the Fetch handshake. We do not read the body anyway (the
	// token travels in the response header), so widest-possible Accept
	// is correct.
	resp, err := call(ctx, destName, http.MethodGet, c.fetchPath,
		http.Header{
			"X-CSRF-Token": []string{"Fetch"},
			"Accept":       []string{"*/*"},
		}, nil)
	if err != nil {
		return nil, fmt.Errorf("csrf fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("csrf fetch %s returned status %d: %s",
			c.fetchPath, resp.StatusCode, strings.TrimSpace(string(bodySnippet)))
	}
	token := resp.Header.Get("X-CSRF-Token")
	if token == "" {
		return nil, fmt.Errorf("csrf fetch %s returned empty X-CSRF-Token header", c.fetchPath)
	}
	return &csrfState{token: token, cookies: resp.Cookies()}, nil
}

func (c *CSRF) invalidate(destName string) {
	c.mu.Lock()
	delete(c.states, destName)
	c.mu.Unlock()
}
