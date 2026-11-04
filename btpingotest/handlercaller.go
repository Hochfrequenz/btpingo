package btpingotest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/internal/fwdheader"
	"github.com/hochfrequenz/btpingo/internal/limitbody"
	"github.com/hochfrequenz/btpingo/internal/pathsuffix"
)

// DefaultDestinationName is the destination name a HandlerCaller serves
// unless WithDestinationName says otherwise.
const DefaultDestinationName = "SAP"

// mockHost is the Host of the requests a HandlerCaller hands to its handler.
const mockHost = "sap.mock"

var _ btpingo.OnPremCaller = (*HandlerCaller)(nil)

// HandlerCaller is a btpingo.OnPremCaller that serves an http.Handler
// in-process instead of calling a SAP system through the Cloud
// Connector. It behaves like btpingo.Service.CallOnPremise wherever a
// caller can see it:
//
//   - the destination name must match, otherwise the error wraps
//     btpingo.ErrDestinationNotFound, as the Destination service lookup
//     does;
//   - the same path-suffix rules (no ".." and no "%");
//   - inbound headers are filtered as Service does (Authorization, hop-by-hop
//     headers and Host dropped, Cookie reduced to SAP session cookies) and
//     User-Agent defaults to btpingo.DefaultUserAgent;
//   - the response body is capped (default
//     btpingo.DefaultOnPremResponseSizeLimit); reading past the cap yields
//     btpingo.ErrOnPremResponseTooLarge;
//   - the context is honoured.
//
// Differences: the handler's answer is buffered before it is returned (no
// streaming), there is no retry on 401 and no CSRF handling.
// Safe for concurrent use if the handler is.
type HandlerCaller struct {
	handler   http.Handler
	dest      string
	limit     int64
	userAgent string
	fault     func(*http.Request) error
}

// HandlerCallerOption configures NewHandlerCaller.
type HandlerCallerOption func(*HandlerCaller)

// WithDestinationName sets the one destination name the caller serves
// (default DefaultDestinationName). Any other name fails like an
// unknown destination.
func WithDestinationName(name string) HandlerCallerOption {
	return func(c *HandlerCaller) { c.dest = name }
}

// WithResponseSizeLimit sets the cap on the response body, like
// btpingo.WithOnPremResponseSizeLimit. Zero or negative values keep the
// default, as they do for the Service.
func WithResponseSizeLimit(bytes int64) HandlerCallerOption {
	return func(c *HandlerCaller) {
		if bytes > 0 {
			c.limit = bytes
		}
	}
}

// WithUserAgent sets the User-Agent sent when the caller supplies none,
// like btpingo.WithUserAgent. An empty value keeps the default.
func WithUserAgent(ua string) HandlerCallerOption {
	return func(c *HandlerCaller) {
		if ua != "" {
			c.userAgent = ua
		}
	}
}

// WithTransportFault installs a hook that runs on every call after the
// request has been built (so it sees the filtered headers) and before
// the handler. A non-nil error is returned from CallOnPremise as if the
// transport had failed before any response, and the handler is not run.
func WithTransportFault(fn func(req *http.Request) error) HandlerCallerOption {
	return func(c *HandlerCaller) { c.fault = fn }
}

// WithTransportError makes every call fail with err before any response.
func WithTransportError(err error) HandlerCallerOption {
	return WithTransportFault(func(*http.Request) error { return err })
}

// NewHandlerCaller returns a HandlerCaller serving h.
func NewHandlerCaller(h http.Handler, opts ...HandlerCallerOption) *HandlerCaller {
	c := &HandlerCaller{
		handler:   h,
		dest:      DefaultDestinationName,
		limit:     btpingo.DefaultOnPremResponseSizeLimit,
		userAgent: btpingo.DefaultUserAgent,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// CallOnPremise implements btpingo.OnPremCaller.
func (c *HandlerCaller) CallOnPremise(ctx context.Context, destName, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error) {
	if err := pathsuffix.Check(pathSuffix); err != nil {
		return nil, err
	}
	if destName != c.dest {
		return nil, fmt.Errorf("destination lookup: %w", fmt.Errorf("%w: %q", btpingo.ErrDestinationNotFound, destName))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	target := "http://" + mockHost
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
	fwdheader.Forward(req.Header, headers)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	// Make it look like a server-side request (a server never sees an empty path).
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}
	req.RequestURI = req.URL.RequestURI()
	req.RemoteAddr = "192.0.2.1:1234"
	if req.Body == nil {
		req.Body = http.NoBody
	}

	if c.fault != nil {
		if err := c.fault(req); err != nil {
			return nil, err
		}
	}

	// The handler runs in its own goroutine and owns the recorder; if the
	// context ends first we return without touching it, so a handler that
	// ignores its context cannot make the caller hang or race.
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		rec := httptest.NewRecorder()
		defer func() {
			if p := recover(); p != nil {
				done <- result{err: fmt.Errorf("on-prem handler panicked: %v", p)}
			}
		}()
		c.handler.ServeHTTP(rec, req)
		done <- result{resp: rec.Result()}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		if err := ctx.Err(); err != nil {
			_ = r.resp.Body.Close()
			return nil, err
		}
		r.resp.Request = req
		r.resp.Body = limitbody.New(r.resp.Body, c.limit, btpingo.ErrOnPremResponseTooLarge)
		return r.resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
