package btpingo_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/internal/testkit"
)

// FuzzCallOnPremise_StaysOnDestinationOrigin: whatever the caller-supplied
// path suffix, no request may reach the fake Cloud Connector proxy for an
// origin other than the destination's (strayCalls counts those, CONNECT
// included). This is the property CodeQL's go/request-forgery query cannot
// see: the host is pinned by comparison against the configured destination,
// not against a constant. `go test` runs the seeds; run it with
// `-fuzz FuzzCallOnPremise_StaysOnDestinationOrigin` to search further.
func FuzzCallOnPremise_StaysOnDestinationOrigin(f *testing.F) {
	for _, seed := range []string{"/x", "//evil.example/x", "@evil.example/x", "/\\evil.example", "?x=http://evil", "#frag", ":80@evil/x",
		"/%2e%2e/", "../../x", "http://evil.example/", "//evil.example:8000/x", "\\\\evil", "/redirect-off-host", "/redirect-other-scheme", "/redirect-other-port"} {
		f.Add(seed)
	}
	s := testkit.NewRedirectStack(f)
	svc, err := btpingo.NewService(s.Env)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, suffix string) {
		before := s.StrayCalls.Load()
		resp, _ := svc.CallOnPremise(context.Background(), "D", http.MethodGet, suffix, nil, nil)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if got := s.StrayCalls.Load() - before; got != 0 {
			t.Fatalf("suffix %q reached a foreign origin %d time(s)", suffix, got)
		}
	})
}
