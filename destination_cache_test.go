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

// Test_DestinationCache_CachesWithinTTL is the core guard: without the
// cache, every CallOnPremise pays a full Destination-service round
// trip. A second Lookup within the TTL must
// not touch the server again.
func Test_DestinationCache_CachesWithinTTL(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://sap-%d","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`, n)
	}))
	defer srv.Close()

	cred := &btpingo.DestCredentials{URI: srv.URL}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)

	d1, err := c.Lookup(context.Background(), cred, "t", "D")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, d1.URL, is.EqualTo("http://sap-1"))

	d2, err := c.Lookup(context.Background(), cred, "t", "D")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, d2.URL, is.EqualTo("http://sap-1")) // cached, not "http://sap-2"
	then.AssertThat(t, int(calls.Load()), is.EqualTo(1))
}

func Test_DestinationCache_RefetchesAfterTTLExpiry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://sap-%d","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`, n)
	}))
	defer srv.Close()

	cred := &btpingo.DestCredentials{URI: srv.URL}
	// A TTL of ~0 (a few ms) forces the second call past expiry without
	// a real sleep-based flake risk from a long TTL.
	c := btpingo.NewDestinationCache(srv.Client(), time.Millisecond)

	first, _ := c.Lookup(context.Background(), cred, "t", "D")
	time.Sleep(20 * time.Millisecond)
	second, err := c.Lookup(context.Background(), cred, "t", "D")

	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, first.URL, is.EqualTo("http://sap-1"))
	then.AssertThat(t, second.URL, is.EqualTo("http://sap-2"))
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))
}

func Test_DestinationCache_RefetchesAfterInvalidate(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://sap-%d","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`, n)
	}))
	defer srv.Close()

	cred := &btpingo.DestCredentials{URI: srv.URL}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)

	first, _ := c.Lookup(context.Background(), cred, "t", "D")
	c.Invalidate(cred, "D")
	second, _ := c.Lookup(context.Background(), cred, "t", "D")

	then.AssertThat(t, first.URL, is.EqualTo("http://sap-1"))
	then.AssertThat(t, second.URL, is.EqualTo("http://sap-2"))
}

// Test_DestinationCache_KeyIgnoresBearer pins the cache-key design
// choice the cache depends on: a rotated bearer token must not
// defeat the cache, because the destination's own content does not
// depend on which valid token was used to ask for it.
func Test_DestinationCache_KeyIgnoresBearer(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://sap","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`)
	}))
	defer srv.Close()

	cred := &btpingo.DestCredentials{URI: srv.URL}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)

	_, err := c.Lookup(context.Background(), cred, "bearer-1", "D")
	then.AssertThat(t, err, is.Nil())
	_, err = c.Lookup(context.Background(), cred, "bearer-2-after-rotation", "D")
	then.AssertThat(t, err, is.Nil())

	then.AssertThat(t, int(calls.Load()), is.EqualTo(1))
}

// Test_DestinationCache_KeysByCredAndName confirms the cache does not
// collapse two genuinely different destinations (or the same name
// under a different subaccount's Destination service) into one entry.
func Test_DestinationCache_KeysByCredAndName(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		name := r.URL.Path[len("/destination-configuration/v1/destinations/"):]
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":%q,"Type":"HTTP","URL":"http://%s","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`, name, name)
	}))
	defer srv.Close()

	cred := &btpingo.DestCredentials{URI: srv.URL}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)

	a, err := c.Lookup(context.Background(), cred, "t", "A")
	then.AssertThat(t, err, is.Nil())
	b, err := c.Lookup(context.Background(), cred, "t", "B")
	then.AssertThat(t, err, is.Nil())

	then.AssertThat(t, a.URL, is.EqualTo("http://A"))
	then.AssertThat(t, b.URL, is.EqualTo("http://B"))
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))
}

// Test_DestinationCache_KeysByClientID guards the multi-tenant case: two
// bindings that share a Destination-service URI but carry different
// ClientIDs must not collapse into one cache entry, or one tenant's
// lookup would silently serve another tenant's cached destination.
func Test_DestinationCache_KeysByClientID(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://sap","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`)
	}))
	defer srv.Close()

	credA := &btpingo.DestCredentials{URI: srv.URL, ClientID: "tenant-a"}
	credB := &btpingo.DestCredentials{URI: srv.URL, ClientID: "tenant-b"}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)

	_, err := c.Lookup(context.Background(), credA, "t", "D")
	then.AssertThat(t, err, is.Nil())
	_, err = c.Lookup(context.Background(), credB, "t", "D")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))

	// A repeat lookup for the first tenant must still be a cache hit.
	_, err = c.Lookup(context.Background(), credA, "t", "D")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))
}

// Test_DestinationCache_KeysByURL covers two *DestCredentials that share
// a URI and a ClientID — the same binding — but differ in the
// tenant-subdomain token URL, the shape a regional Destination-service
// endpoint hands to separate subscriber tenants of one binding. They
// must not collide on the same cache entry.
func Test_DestinationCache_KeysByURL(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://sap","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`)
	}))
	defer srv.Close()

	credTenant1 := &btpingo.DestCredentials{URI: srv.URL, ClientID: "binding-1", URL: "https://tenant1.authentication.eu10.hana.ondemand.com"}
	credTenant2 := &btpingo.DestCredentials{URI: srv.URL, ClientID: "binding-1", URL: "https://tenant2.authentication.eu10.hana.ondemand.com"}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)

	_, err := c.Lookup(context.Background(), credTenant1, "t", "D")
	then.AssertThat(t, err, is.Nil())
	_, err = c.Lookup(context.Background(), credTenant2, "t", "D")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))

	// A repeat lookup for the first tenant must still be a cache hit.
	_, err = c.Lookup(context.Background(), credTenant1, "t", "D")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))
}

// Test_DestinationCache_KeyIsUnambiguous pins a length-prefixed cacheKey:
// a plain "|"-joined key lets the separator inside one field's own value
// shift where a neighboring field's boundary falls, so two distinct
// (URI, URL, ClientID, name) tuples can join into the identical string.
// Here credA's URL "a|b" and credB's URI suffix "|a" would, under a naive
// join, both produce ".../x|a|b|c|d" — a collision that must not happen.
func Test_DestinationCache_KeyIsUnambiguous(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://sap","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`)
	}))
	defer srv.Close()

	credA := &btpingo.DestCredentials{URI: srv.URL + "/x", URL: "a|b", ClientID: "c"}
	credB := &btpingo.DestCredentials{URI: srv.URL + "/x|a", URL: "b", ClientID: "c"}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)

	_, err := c.Lookup(context.Background(), credA, "t", "d")
	then.AssertThat(t, err, is.Nil())
	_, err = c.Lookup(context.Background(), credB, "t", "d")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))

	// Repeats for each must still be cache hits.
	_, err = c.Lookup(context.Background(), credA, "t", "d")
	then.AssertThat(t, err, is.Nil())
	_, err = c.Lookup(context.Background(), credB, "t", "d")
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, int(calls.Load()), is.EqualTo(2))
}

func Test_DestinationCache_PropagatesLookupError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cred := &btpingo.DestCredentials{URI: srv.URL}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)
	_, err := c.Lookup(context.Background(), cred, "t", "Missing")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

func Test_DestinationCache_RequiresBinding(t *testing.T) {
	c := btpingo.NewDestinationCache(nil, time.Hour)
	_, err := c.Lookup(context.Background(), nil, "t", "D")
	then.AssertThat(t, err, is.Not(is.Nil()))
}

// Test_DestinationCache_CollapsesConcurrentMisses mirrors
// Test_TokenFetcher_CollapsesConcurrentMisses: a burst of requests
// hitting a cold cache must not become a burst of concurrent
// Destination-service calls.
func Test_DestinationCache_CollapsesConcurrentMisses(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		n := calls.Add(1)
		_, _ = fmt.Fprintf(w, `{"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":"http://sap-%d","Authentication":"NoAuthentication","ProxyType":"OnPremise"}}`, n)
	}))
	defer srv.Close()

	cred := &btpingo.DestCredentials{URI: srv.URL}
	c := btpingo.NewDestinationCache(srv.Client(), time.Hour)

	var wg sync.WaitGroup
	var successes atomic.Int32
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
			if _, err := c.Lookup(context.Background(), cred, "t", "D"); err == nil {
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
