package btpingotest

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/internal/fwdheader"
	"github.com/hochfrequenz/btpingo/internal/limitbody"
	"github.com/hochfrequenz/btpingo/internal/onprem"
	"github.com/hochfrequenz/btpingo/internal/pathsuffix"
)

// DefaultDestinationName is the destination name a HandlerCaller serves
// unless WithDestinationName says otherwise.
const DefaultDestinationName = "SAP"

var (
	_ btpingo.OnPremCaller  = (*HandlerCaller)(nil)
	_ btpingo.OnPremMutator = (*HandlerCaller)(nil)
)

// HandlerCaller is a btpingo.OnPremCaller and btpingo.OnPremMutator that
// serves an http.Handler in-process instead of calling a SAP system
// through the Cloud Connector. The handler sits behind a real HTTP
// server on a loopback port and is called by a real http.Client set up
// like the one of btpingo.Service, so what a caller can observe is what
// the Service would give:
//
//   - the destination name must match, otherwise the error wraps
//     btpingo.ErrDestinationNotFound, as the Destination service lookup does;
//   - the same path-suffix rules (no ".." and no "%");
//   - inbound headers are filtered as Service does (Authorization, hop-by-hop
//     headers and Host dropped, Cookie reduced to SAP session cookies) and
//     User-Agent defaults to btpingo.DefaultUserAgent;
//   - same-origin redirects are followed, cross-origin ones fail with
//     btpingo.ErrOnPremCrossOriginRedirect, at most 10 hops;
//   - real HTTP semantics: Content-Length, Date, HEAD, transparent gzip
//     decoding, transport errors as *url.Error;
//   - the response body is capped (default btpingo.DefaultOnPremResponseSizeLimit);
//     reading past the cap yields btpingo.ErrOnPremResponseTooLarge;
//   - a 401 is retried once when the call has no body;
//   - CallOnPremiseMutating runs the same CSRF handshake as the Service;
//   - the context is honoured.
//
// Not mirrored: destination, connectivity and authenticator handling
// (the handler sees no Authorization header from them) and the
// Cloud Connector proxy.
//
// The call crosses a real HTTP connection, so values of the caller's
// context do not reach the handler (only its cancellation does).
// A handler that ignores its request context keeps running (and its
// goroutine lives) until it returns, even after the call has returned
// with the context error.
//
// Call Close when done. Safe for concurrent use if the handler is.
// For tests and local mocks only; never import btpingotest in production code.
type HandlerCaller struct {
	handler   http.Handler
	dest      string
	limit     int64
	userAgent string
	timeout   time.Duration
	fault     func(*http.Request) error
	csrfPath  string

	csrf   *onprem.CSRF
	client *http.Client
	tr     *http.Transport
	srv    *http.Server
	base   string
	once   sync.Once
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

// WithTimeout sets the client timeout of a call, like
// btpingo.WithOnPremiseTimeout (default btpingo.DefaultOnPremiseTimeout).
// Zero keeps the default.
func WithTimeout(d time.Duration) HandlerCallerOption {
	return func(c *HandlerCaller) {
		if d != 0 {
			c.timeout = d
		}
	}
}

// WithCSRFFetchPath sets the path of the CSRF token fetch, like
// btpingo.WithCSRFFetchPath (default btpingo.DefaultCSRFFetchPath).
func WithCSRFFetchPath(path string) HandlerCallerOption {
	return func(c *HandlerCaller) {
		if path != "" {
			c.csrfPath = path
		}
	}
}

// WithTransportFault installs a hook that runs on every request after
// it has been built (so it sees the filtered headers) and before it is
// sent. A non-nil error is returned from the call as if the transport
// had failed before any response, and the handler is not run.
func WithTransportFault(fn func(req *http.Request) error) HandlerCallerOption {
	return func(c *HandlerCaller) { c.fault = fn }
}

// NewHandlerCaller starts a loopback server for h and returns a caller
// for it. It fails only if no loopback port can be opened.
func NewHandlerCaller(h http.Handler, opts ...HandlerCallerOption) (*HandlerCaller, error) {
	c := &HandlerCaller{
		handler:   h,
		dest:      DefaultDestinationName,
		limit:     btpingo.DefaultOnPremResponseSizeLimit,
		userAgent: btpingo.DefaultUserAgent,
		timeout:   btpingo.DefaultOnPremiseTimeout,
		csrfPath:  btpingo.DefaultCSRFFetchPath,
	}
	for _, o := range opts {
		o(c)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("btpingotest: listen: %w", err)
	}
	c.base = "http://" + ln.Addr().String()
	c.srv = &http.Server{
		Handler: h,
		// A panicking handler aborts the connection like on any server; keep
		// the stack trace out of test output.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = c.srv.Serve(ln) }()

	c.tr = http.DefaultTransport.(*http.Transport).Clone()
	c.tr.Proxy = nil
	c.client = &http.Client{
		Transport:     c.tr,
		Timeout:       c.timeout,
		CheckRedirect: onprem.RedirectPolicy(btpingo.ErrOnPremCrossOriginRedirect),
	}
	c.csrf = onprem.NewCSRF(c.csrfPath)
	return c, nil
}

// Close stops the server and drops idle connections. It does not wait for
// running handlers. Calling it more than once is fine.
func (c *HandlerCaller) Close() {
	c.once.Do(func() {
		c.tr.CloseIdleConnections()
		_ = c.srv.Close()
	})
}

// CallOnPremise implements btpingo.OnPremCaller.
func (c *HandlerCaller) CallOnPremise(ctx context.Context, destName, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error) {
	if err := pathsuffix.Check(pathSuffix); err != nil {
		return nil, err
	}
	if destName != c.dest {
		return nil, fmt.Errorf("destination lookup: %w", fmt.Errorf("%w: %q", btpingo.ErrDestinationNotFound, destName))
	}
	resp, err := c.callOnce(ctx, method, pathSuffix, headers, body)
	if err != nil {
		return nil, err
	}
	// Same retry decision as Service: one more attempt on 401 when the
	// caller handed over no body.
	if onprem.Retry401(resp.StatusCode, body) {
		_ = resp.Body.Close()
		return c.callOnce(ctx, method, pathSuffix, headers, nil)
	}
	return resp, nil
}

// CallOnPremiseMutating implements btpingo.OnPremMutator with the same
// CSRF handshake as btpingo.Service (token fetch, session cookies, one
// retry on 403 with X-CSRF-Token: Required); the logic is shared.
func (c *HandlerCaller) CallOnPremiseMutating(ctx context.Context, destName, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error) {
	return c.csrf.Do(ctx, c.CallOnPremise, destName, method, pathSuffix, headers, body)
}

func (c *HandlerCaller) callOnce(ctx context.Context, method, pathSuffix string, headers http.Header, body io.Reader) (*http.Response, error) {
	target := c.base
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
	if c.fault != nil {
		if err := c.fault(req); err != nil {
			return nil, err
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body = limitbody.New(resp.Body, c.limit, btpingo.ErrOnPremResponseTooLarge)
	return resp, nil
}
