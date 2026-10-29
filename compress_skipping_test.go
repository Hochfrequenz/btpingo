package btpingo_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/hochfrequenz/btpingo"
)

// skippingBody is above gzhttp's minimum size, so it is compressed whenever the handler is wrapped.
var skippingBody = []byte(strings.Repeat("a-fairly-long-value-for-compression-", 200))

func skippingMux() *http.ServeMux {
	mux := http.NewServeMux()
	for path, ctype := range map[string]string{
		"/test.v1.TestService/Call": "application/grpc",
		"/api/v1/items":             "application/json",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Content-Length", strconv.Itoa(len(skippingBody)))
			_, _ = w.Write(skippingBody)
		})
	}
	return mux
}

func contentEncodingOf(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Header().Get("Content-Encoding")
}

func Test_CompressHandlerSkipping_PrefixedPathsAreNotCompressed(t *testing.T) {
	h := btpingo.CompressHandlerSkipping(skippingMux(), "/test.v1.TestService/")
	if got := contentEncodingOf(t, h, "/test.v1.TestService/Call"); got != "" {
		t.Fatalf("Content-Encoding on prefixed path = %q, want none", got)
	}
	if got := contentEncodingOf(t, h, "/api/v1/items"); got != gzipEncoding {
		t.Fatalf("Content-Encoding on other path = %q, want gzip", got)
	}
}

func Test_CompressHandlerSkipping_NoPrefixesBehavesLikeCompressHandler(t *testing.T) {
	h := btpingo.CompressHandlerSkipping(skippingMux())
	for _, path := range []string{"/test.v1.TestService/Call", "/api/v1/items"} {
		if got := contentEncodingOf(t, h, path); got != gzipEncoding {
			t.Fatalf("%s: Content-Encoding = %q, want gzip", path, got)
		}
	}
}

func Test_CompressHandlerSkipping_SkippedPathsBypassTheContentLengthGuard(t *testing.T) {
	// a handler that declares more than it writes: CompressHandler would abort, a skipped path must not
	h := btpingo.CompressHandlerSkipping(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}), "/test.v1.TestService/")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/test.v1.TestService/Call", nil))
	if w.Body.String() != "short" {
		t.Fatalf("body = %q", w.Body.String())
	}
}
