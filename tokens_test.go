package btpingo_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo"
)

func Test_TokenFetcher_CachesWithinTTL(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"bearer","expires_in":3600}`, calls.Load())
	}))
	defer srv.Close()

	f := btpingo.NewTokenFetcher(srv.Client())

	tok1, err := f.Fetch(context.Background(), srv.URL, "cid", "csec")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, tok1, is.EqualTo("tok-1"))

	tok2, err := f.Fetch(context.Background(), srv.URL, "cid", "csec")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, tok2, is.EqualTo("tok-1")) // cached
	then.AssertThat(t, int(calls.Load()), is.EqualTo(1))
}

func Test_TokenFetcher_RefetchesAfterInvalidate(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"bearer","expires_in":3600}`, n)
	}))
	defer srv.Close()

	f := btpingo.NewTokenFetcher(srv.Client())

	first, _ := f.Fetch(context.Background(), srv.URL, "cid", "csec")
	f.Invalidate(srv.URL, "cid")
	second, _ := f.Fetch(context.Background(), srv.URL, "cid", "csec")

	then.AssertThat(t, first, is.EqualTo("tok-1"))
	then.AssertThat(t, second, is.EqualTo("tok-2"))
}

func Test_TokenFetcher_RefetchesNearExpiry(t *testing.T) {
	// expires_in=1 means the leeway (30s) always triggers a refresh.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"bearer","expires_in":1}`, n)
	}))
	defer srv.Close()

	f := btpingo.NewTokenFetcher(srv.Client())
	_, _ = f.Fetch(context.Background(), srv.URL, "cid", "csec")
	time.Sleep(10 * time.Millisecond)
	_, err := f.Fetch(context.Background(), srv.URL, "cid", "csec")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))
}

func Test_TokenFetcher_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	f := btpingo.NewTokenFetcher(srv.Client())
	_, err := f.Fetch(context.Background(), srv.URL, "cid", "csec")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_TokenFetcher_RejectsMissingInputs(t *testing.T) {
	f := btpingo.NewTokenFetcher(nil)
	_, err := f.Fetch(context.Background(), "", "cid", "csec")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_TokenFetcher_RejectsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	f := btpingo.NewTokenFetcher(srv.Client())
	_, err := f.Fetch(context.Background(), srv.URL, "c", "s")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_TokenFetcher_RejectsEmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"","expires_in":3600}`))
	}))
	defer srv.Close()
	f := btpingo.NewTokenFetcher(srv.Client())
	_, err := f.Fetch(context.Background(), srv.URL, "c", "s")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_TokenFetcher_HandlesTransportError(t *testing.T) {
	// Server closed before Fetch — triggers the httpClient.Do error path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srvURL := srv.URL
	srv.Close()
	f := btpingo.NewTokenFetcher(&http.Client{Timeout: 100 * time.Millisecond})
	_, err := f.Fetch(context.Background(), srvURL, "c", "s")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_TokenFetcher_CollapsesConcurrentMisses(t *testing.T) {
	// 50 goroutines race into a cold cache. Without singleflight each
	// would trigger its own exchange; with it, exactly one does.
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		n := calls.Add(1)
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"bearer","expires_in":3600}`, n)
	}))
	defer srv.Close()

	f := btpingo.NewTokenFetcher(srv.Client())
	var wg sync.WaitGroup
	var successes atomic.Int32
	// A real barrier instead of a fixed sleep. The old version gave 50
	// goroutines 50ms to get scheduled and reach singleflight; under the
	// race detector on a loaded two-core runner that is a guess, and a
	// goroutine arriving after the release finds a filled cache — no
	// second exchange, but no proof of collapsing either. Now every
	// goroutine is parked before any of them starts, and each signals
	// immediately before entering Fetch, so the release cannot happen
	// until all 50 are at the door.
	start := make(chan struct{})
	var parked, atTheDoor sync.WaitGroup
	parked.Add(50)
	atTheDoor.Add(50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parked.Done()
			<-start
			atTheDoor.Done()
			if _, err := f.Fetch(context.Background(), srv.URL, "cid", "csec"); err == nil {
				successes.Add(1)
			}
		}()
	}
	parked.Wait()
	close(start)
	atTheDoor.Wait()
	close(release)
	wg.Wait()

	then.AssertThat(t, int(successes.Load()), is.EqualTo(50))
	then.AssertThat(t, int(calls.Load()), is.EqualTo(1))
}
