package btpingo

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"time"
)

// RetryPolicy controls [Retry] and [RetryMutating].
type RetryPolicy struct {
	// MaxAttempts includes the initial call. Values <= 0 default to 2.
	MaxAttempts int
	// Backoff defaults to 200ms when <= 0. Each wait is independently
	// jittered between half of Backoff and Backoff, inclusive.
	Backoff time.Duration
	// Idempotent explicitly permits RetryMutating to repeat a call.
	// Rebuilding a request body alone does not make an operation idempotent.
	Idempotent bool
	// Clock supplies backoff waits; nil uses time.After.
	Clock interface {
		After(time.Duration) <-chan time.Time
	}
}

// Retryable reports whether an attempt is worth repeating: a plain transport
// error classified by [ClassifyOnPremError], or an HTTP 502 or 503 without an
// error. Timeouts (including net.Error timeouts), cancellation, missing
// destinations, oversized responses, and all other statuses are not retried.
// It neither reads nor closes resp.Body and does not inspect application codes.
func Retryable(resp *http.Response, err error) bool {
	if err != nil {
		kind, _ := ClassifyOnPremError(err)
		var netErr net.Error
		return resp == nil && kind == OnPremFailureTransport &&
			!(errors.As(err, &netErr) && netErr.Timeout())
	}
	return resp != nil && (resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusServiceUnavailable)
}

// Retry calls fn for a read-only operation up to MaxAttempts times, using
// [Retryable] to decide whether to repeat it. For mutating operations use
// [RetryMutating] instead: fn is opaque, so Retry cannot infer retry safety.
//
// Each invocation must rebuild its request body; an io.Reader is read-once.
// The final response and error are returned unchanged, and the caller owns
// that response body. Discarded bodies are closed before waiting. If ctx is
// done, Retry closes any discarded response and returns nil, ctx.Err().
// fn must honor ctx so cancellation can interrupt an in-flight call.
//
// HTTP 401/403 are not retried here; the service's cache/CSRF retries remain
// responsible for those cases.
func Retry(ctx context.Context, p RetryPolicy, fn func(context.Context) (*http.Response, error)) (*http.Response, error) {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = 2
	}
	if p.Backoff <= 0 {
		p.Backoff = 200 * time.Millisecond
	}
	after := time.After
	if p.Clock != nil {
		after = p.Clock.After
	}
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := fn(ctx)
		ctxErr := ctx.Err()
		if ctxErr == nil && (attempt >= p.MaxAttempts || !Retryable(resp, err)) {
			return resp, err
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if ctxErr != nil {
			return nil, ctxErr
		}
		delay := p.Backoff/2 + time.Duration(rand.Int64N(int64(p.Backoff-p.Backoff/2)+1))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-after(delay):
		}
	}
}

// RetryMutating is [Retry] for mutating operations, including calls to
// [Service.CallOnPremiseMutating]. Unless p.Idempotent is true, fn is called
// at most once regardless of MaxAttempts. An ambiguous transport failure
// may have applied the mutation already; only the caller can establish that
// repeating it is safe (for example, through an upstream idempotency key).
func RetryMutating(ctx context.Context, p RetryPolicy, fn func(context.Context) (*http.Response, error)) (*http.Response, error) {
	if !p.Idempotent {
		p.MaxAttempts = 1
	}
	return Retry(ctx, p, fn)
}
