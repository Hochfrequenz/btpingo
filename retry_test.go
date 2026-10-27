package btpingo_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hochfrequenz/btpingo"
)

type retryClock struct {
	delays []time.Duration
	wait   func() <-chan time.Time
}

func (c *retryClock) After(d time.Duration) <-chan time.Time {
	c.delays = append(c.delays, d)
	if c.wait != nil {
		return c.wait()
	}
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

type retryBody struct {
	io.Reader
	closes int
}

func (b *retryBody) Close() error {
	b.closes++
	return nil
}

func TestRetryRules(t *testing.T) {
	transportErr := errors.New("connection reset")
	tests := []struct {
		name   string
		status int
		err    error
		retry  bool
	}{
		{name: "transport", err: transportErr, retry: true},
		{name: "wrapped transport", err: fmt.Errorf("call: %w", transportErr), retry: true},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "wrapped deadline", err: fmt.Errorf("call: %w", context.DeadlineExceeded)},
		{name: "network timeout", err: &net.DNSError{IsTimeout: true}},
		{name: "canceled", err: context.Canceled},
		{name: "wrapped canceled", err: fmt.Errorf("call: %w", context.Canceled)},
		{name: "destination", err: btpingo.ErrDestinationNotFound},
		{name: "wrapped destination", err: fmt.Errorf("call: %w", btpingo.ErrDestinationNotFound)},
		{name: "oversized", err: btpingo.ErrOnPremResponseTooLarge},
		{name: "wrapped oversized", err: fmt.Errorf("call: %w", btpingo.ErrOnPremResponseTooLarge)},
		{name: "nil result"},
		{name: "response with transport error", status: 502, err: transportErr},
		{name: "response with deadline", status: 503, err: context.DeadlineExceeded},
	}
	// Exhaustively check statuses, not just a selection of common failures.
	for status := 100; status <= 599; status++ {
		tests = append(tests, struct {
			name   string
			status int
			err    error
			retry  bool
		}{
			name: fmt.Sprintf("HTTP %d", status), status: status,
			retry: status == 502 || status == 503,
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			body := &retryBody{Reader: strings.NewReader(`{"error":{"code":"application_error"}}`)}
			if tt.status != 0 {
				resp = &http.Response{StatusCode: tt.status, Body: body}
			}
			if got := btpingo.Retryable(resp, tt.err); got != tt.retry {
				t.Fatalf("Retryable = %v, want %v", got, tt.retry)
			}
			if body.closes != 0 {
				t.Fatal("Retryable closed body")
			}
			clock := &retryClock{}
			calls := 0
			gotResp, gotErr := btpingo.Retry(context.Background(), btpingo.RetryPolicy{Clock: clock}, func(context.Context) (*http.Response, error) {
				calls++
				return resp, tt.err
			})
			wantCalls := 1
			if tt.retry {
				wantCalls = 2
			}
			if calls != wantCalls || len(clock.delays) != wantCalls-1 {
				t.Fatalf("calls = %d, waits = %d; want %d calls", calls, len(clock.delays), wantCalls)
			}
			if gotResp != resp || gotErr != tt.err {
				t.Fatal("final result was not preserved")
			}
			wantCloses := 0
			if resp != nil && tt.retry {
				wantCloses = 1
			}
			if body.closes != wantCloses {
				t.Fatalf("body closed %d times, want %d", body.closes, wantCloses)
			}
			for _, d := range clock.delays {
				if d < 100*time.Millisecond || d > 200*time.Millisecond {
					t.Fatalf("default jitter outside 100–200ms: %s", d)
				}
			}
		})
	}
}

func TestRetryAttempts(t *testing.T) {
	for _, attempts := range []int{-1, 0, 1, 2, 4} {
		t.Run(fmt.Sprint(attempts), func(t *testing.T) {
			clock := &retryClock{}
			calls := 0
			wantCalls := attempts
			if attempts <= 0 {
				wantCalls = 2
			}
			resp, err := btpingo.Retry(context.Background(), btpingo.RetryPolicy{
				MaxAttempts: attempts, Backoff: time.Second, Clock: clock,
			}, func(context.Context) (*http.Response, error) {
				calls++
				return nil, io.ErrUnexpectedEOF
			})
			if resp != nil || err != io.ErrUnexpectedEOF || calls != wantCalls || len(clock.delays) != wantCalls-1 {
				t.Fatalf("result = %v, %v; calls = %d, waits = %d", resp, err, calls, len(clock.delays))
			}
			for _, d := range clock.delays {
				if d < time.Second/2 || d > time.Second {
					t.Fatalf("custom jitter outside 0.5–1s: %s", d)
				}
			}
		})
	}
}

func TestRetryRebuildsBodyAndPreservesFinalResponse(t *testing.T) {
	clock := &retryClock{}
	discarded := &retryBody{Reader: strings.NewReader("unavailable")}
	finalBody := &retryBody{Reader: strings.NewReader("ok")}
	final := &http.Response{StatusCode: http.StatusOK, Body: finalBody}
	defer final.Body.Close()
	calls := 0
	ctx := context.WithValue(context.Background(), struct{}{}, "request")
	resp, err := btpingo.Retry(ctx, btpingo.RetryPolicy{MaxAttempts: 4, Clock: clock}, func(gotCtx context.Context) (*http.Response, error) {
		if gotCtx != ctx {
			t.Fatal("callback context changed")
		}
		req, reqErr := http.NewRequestWithContext(gotCtx, http.MethodGet, "http://example.test", strings.NewReader("fresh body"))
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		body, readErr := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if readErr != nil || string(body) != "fresh body" {
			t.Fatalf("request body = %q, %v", body, readErr)
		}
		calls++
		if calls == 1 {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: discarded}, nil
		}
		if discarded.closes != 1 {
			t.Fatal("discarded body was not closed before retry")
		}
		return final, nil
	})
	if err != nil || resp != final || calls != 2 || len(clock.delays) != 1 || finalBody.closes != 0 {
		t.Fatalf("result = %v, %v; calls = %d", resp, err, calls)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("final body = %q, %v", body, err)
	}
}

func TestRetryCancellation(t *testing.T) {
	for _, phase := range []string{"before call", "during call", "during successful call", "during wait", "ready clock"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clock := &retryClock{}
			body := &retryBody{}
			calls := 0
			if phase == "before call" {
				cancel()
			}
			clock.wait = func() <-chan time.Time {
				if body.closes != 1 {
					t.Fatal("body not closed before wait")
				}
				cancel()
				ch := make(chan time.Time, 1)
				if phase == "ready clock" {
					ch <- time.Time{}
				}
				return ch
			}
			resp, err := btpingo.Retry(ctx, btpingo.RetryPolicy{Clock: clock}, func(context.Context) (*http.Response, error) {
				calls++
				status := http.StatusServiceUnavailable
				if phase == "during successful call" {
					status = http.StatusOK
				}
				if phase == "during call" || phase == "during successful call" {
					cancel()
				}
				return &http.Response{StatusCode: status, Body: body}, nil
			})
			wantCalls := 1
			if phase == "before call" {
				wantCalls = 0
			}
			if resp != nil || err != context.Canceled || calls != wantCalls || body.closes != wantCalls {
				t.Fatalf("result = %v, %v; calls = %d, closes = %d", resp, err, calls, body.closes)
			}
		})
	}
}

func TestRetryExpiredContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Time{})
	defer cancel()
	clock := &retryClock{}
	resp, err := btpingo.Retry(ctx, btpingo.RetryPolicy{Clock: clock}, func(context.Context) (*http.Response, error) {
		t.Fatal("callback invoked despite expired context")
		return nil, nil
	})
	if resp != nil || err != context.DeadlineExceeded || len(clock.delays) != 0 {
		t.Fatalf("result = %v, %v; waits = %d", resp, err, len(clock.delays))
	}
}

func TestRetryMutating(t *testing.T) {
	for _, idempotent := range []bool{false, true} {
		for _, status := range []int{0, 502, 503, 504, 403} {
			t.Run(fmt.Sprintf("idempotent=%v/status=%d", idempotent, status), func(t *testing.T) {
				clock := &retryClock{}
				calls := 0
				resp, err := btpingo.RetryMutating(context.Background(), btpingo.RetryPolicy{
					Idempotent: idempotent, Clock: clock,
				}, func(context.Context) (*http.Response, error) {
					calls++
					if status == 0 {
						return nil, io.ErrUnexpectedEOF
					}
					return &http.Response{StatusCode: status}, nil
				})
				wantCalls := 1
				if idempotent && (status == 0 || status == 502 || status == 503) {
					wantCalls = 2
				}
				if calls != wantCalls || len(clock.delays) != wantCalls-1 {
					t.Fatalf("calls = %d, waits = %d; want %d calls", calls, len(clock.delays), wantCalls)
				}
				if status == 0 {
					if resp != nil || err != io.ErrUnexpectedEOF {
						t.Fatalf("result = %v, %v", resp, err)
					}
				} else if err != nil || resp == nil || resp.StatusCode != status {
					t.Fatalf("result = %v, %v", resp, err)
				}
			})
		}
	}
}
