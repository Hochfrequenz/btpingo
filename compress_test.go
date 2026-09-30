package btpingo_test

// compress_test.go exercises the full btpingo.CompressHandler wrapper —
// gzhttp(contentLengthGuard(h)) — the way a service actually wires it
// (srv.Handler = btpingo.CompressHandler(router)). Ported from
// go-sap-btp-cf-template's cmd/server/gzip_test.go and server_test.go,
// adapted to a plain net/http.Handler (an http.ServeMux) instead of a
// *gin.Engine, since this core package stays gin-free.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/gzhttp"
	"github.com/klauspost/compress/zstd"

	"github.com/hochfrequenz/btpingo"
)

// gzipEncoding is the Content-Encoding/Accept-Encoding token value used
// throughout this file.
const gzipEncoding = "gzip"

// bigJSONBody is comfortably above gzhttp's 1024-byte DefaultMinSize.
var bigJSONBody = mustJSON(map[string]any{
	"claims": strings.Repeat("a-fairly-long-claim-value-", 100),
})

// hugeJSONBody is a ~3.4 MB time-series-like JSON payload: repetitive
// enough that gzip should shrink it a lot, but shaped like real telemetry
// rather than one repeated byte.
var hugeJSONBody = mustHugeTimeSeriesJSON(60000)

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func mustHugeTimeSeriesJSON(points int) []byte {
	type point struct {
		Timestamp int64   `json:"timestamp"`
		Value     float64 `json:"value"`
		Sensor    string  `json:"sensor"`
	}
	series := make([]point, points)
	for i := range series {
		series[i] = point{
			Timestamp: 1_700_000_000 + int64(i),
			Value:     float64(i%1000) * 0.125,
			Sensor:    fmt.Sprintf("sensor-%d", i%7),
		}
	}
	return mustJSON(series)
}

func gzipBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// alreadyEncodedPlaintext simulates a handler that already relayed an
// upstream gzip-compressed body byte-for-byte (e.g. a proxy handler
// forwarding a gzip-encoded SAP response, or any handler that sets
// Content-Encoding itself). CompressHandler must pass such a response
// through unmodified rather than double-compressing it.
var alreadyEncodedPlaintext = []byte(`{"already":"gzip-encoded-by-the-handler-itself"}`)

func newMuxServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bigJSONBody)
	})

	mux.HandleFunc("/huge", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(hugeJSONBody)
	})

	mux.HandleFunc("/tiny", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/already-encoded", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", gzipEncoding)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzipBytes(t, alreadyEncodedPlaintext))
	})

	// /ranged simulates a byte-range response: 206 + Content-Range, body
	// well above MinSize. gzhttp must leave a response carrying
	// Content-Range untouched — the bytes are already a slice of a larger
	// representation, so compressing (or not) here has nothing to do with
	// the client's Accept-Encoding and everything to do with not
	// corrupting a byte-exact range.
	mux.HandleFunc("/ranged", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(bigJSONBody)-1, len(bigJSONBody)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(bigJSONBody)
	})

	srv := httptest.NewServer(btpingo.CompressHandler(mux))
	t.Cleanup(srv.Close)
	return srv
}

// newMuxServerCompressEverything is newMuxServer's handler but wrapped
// with gzhttp's MinSize forced to 0. It bypasses CompressHandler and
// exercises gzhttp itself with MinSize(0), so every response — including
// ones below the default 1 KiB threshold — is a candidate for
// compression. It exists solely to prove that a route's already-small
// 404 body survives being run through compression forced on, not just
// left alone because it was too small to bother with.
func newMuxServerCompressEverything(t *testing.T, r http.Handler) *httptest.Server {
	t.Helper()
	wrap, err := gzhttp.NewWrapper(gzhttp.MinSize(0))
	if err != nil {
		t.Fatalf("gzhttp.NewWrapper: %v", err)
	}
	srv := httptest.NewServer(wrap(r))
	t.Cleanup(srv.Close)
	return srv
}

// readRaw reads the raw wire bytes; callers use noAutoDecompressClient
// (a Transport with DisableCompression set) so Go's http.Transport does
// NOT do its own transparent gzip decoding, which would hide the exact
// on-the-wire behaviour under test.
func readRaw(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return raw
}

func gunzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	return out
}

// noAutoDecompressClient returns an *http.Client whose Transport does NOT
// transparently request/decode gzip on our behalf.
func noAutoDecompressClient(srv *httptest.Server) *http.Client {
	c := *srv.Client()
	tr := c.Transport.(*http.Transport).Clone()
	tr.DisableCompression = true
	c.Transport = tr
	return &c
}

func Test_CompressHandler_JSONAboveMinSize_Gzip(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/big", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Encoding"); got != gzipEncoding {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if !strings.Contains(resp.Header.Get("Vary"), "Accept-Encoding") {
		t.Fatalf("Vary = %q, want it to include Accept-Encoding", resp.Header.Get("Vary"))
	}

	raw := readRaw(t, resp)
	got := gunzip(t, raw)
	if !bytes.Equal(got, bigJSONBody) {
		t.Fatalf("decompressed body mismatch: got %d bytes, want %d bytes", len(got), len(bigJSONBody))
	}
}

func Test_CompressHandler_NoAcceptEncoding_Uncompressed(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/big", nil)
	// deliberately no Accept-Encoding header
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty (uncompressed)", got)
	}
	raw := readRaw(t, resp)
	if !bytes.Equal(raw, bigJSONBody) {
		t.Fatalf("body mismatch: got %d bytes, want %d bytes identical to source", len(raw), len(bigJSONBody))
	}
}

func Test_CompressHandler_GzipQZero_Uncompressed(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/big", nil)
	req.Header.Set("Accept-Encoding", "gzip;q=0")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty (client explicitly rejected gzip)", got)
	}
	raw := readRaw(t, resp)
	if !bytes.Equal(raw, bigJSONBody) {
		t.Fatalf("body mismatch: got %d bytes, want %d bytes identical to source", len(raw), len(bigJSONBody))
	}
}

// Test_CompressHandler_UnknownRoute_404Body is the regression test for
// the bug that killed the earlier wrap-the-framework's-ResponseWriter
// approach: a response for a route the mux doesn't recognise must still
// carry its real 404 body, not an empty one.
func Test_CompressHandler_UnknownRoute_404Body(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/this-route-does-not-exist", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}

	raw := readRaw(t, resp)
	var body []byte
	if resp.Header.Get("Content-Encoding") == gzipEncoding {
		body = gunzip(t, raw)
	} else {
		body = raw
	}
	if len(body) == 0 {
		t.Fatalf("404 body is empty; want the mux's real not-found body")
	}
}

// Test_CompressHandler_UnknownRoute_404Body_ForcedCompression is
// Test_CompressHandler_UnknownRoute_404Body's companion: it wraps the mux
// with gzhttp.MinSize(0), so the small 404 body is actually compressed
// this time (not merely eligible), and proves it still round-trips to
// the real not-found body rather than an empty one.
func Test_CompressHandler_UnknownRoute_404Body_ForcedCompression(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/known", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := newMuxServerCompressEverything(t, mux)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/this-route-does-not-exist", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Encoding"); got != gzipEncoding {
		t.Fatalf("Content-Encoding = %q, want gzip (MinSize(0) forces compression of this small body)", got)
	}

	raw := readRaw(t, resp)
	body := gunzip(t, raw)
	if len(body) == 0 {
		t.Fatalf("404 body is empty after forced compression; want the real not-found body")
	}
}

// Test_CompressHandler_AlreadyEncodedResponse_PassedThrough covers a
// handler that already set Content-Encoding itself before
// CompressHandler ever sees the response — e.g. a proxy handler relaying
// an upstream SAP response that was already gzip-encoded. CompressHandler
// must pass it through byte-identical, never double-compress it.
func Test_CompressHandler_AlreadyEncodedResponse_PassedThrough(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/already-encoded", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Encoding"); got != gzipEncoding {
		t.Fatalf("Content-Encoding = %q, want gzip (the handler's own, not a wrapper-added one)", got)
	}

	raw := readRaw(t, resp)
	got := gunzip(t, raw)
	if !bytes.Equal(got, alreadyEncodedPlaintext) {
		t.Fatalf("body was double-compressed or corrupted: got %q", got)
	}
}

func Test_CompressHandler_LargeBody_RoundTripsAndShrinks(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/huge", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Encoding"); got != gzipEncoding {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}

	raw := readRaw(t, resp)
	if len(raw) >= len(hugeJSONBody) {
		t.Fatalf("compressed size %d not smaller than uncompressed size %d", len(raw), len(hugeJSONBody))
	}
	if ratio := float64(len(raw)) / float64(len(hugeJSONBody)); ratio > 0.5 {
		t.Fatalf("compressed size %d is only %.2fx smaller than uncompressed %d; expected well below 0.5x for repetitive JSON",
			len(raw), ratio, len(hugeJSONBody))
	}

	got := gunzip(t, raw)
	if !bytes.Equal(got, hugeJSONBody) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(hugeJSONBody))
	}
}

func Test_CompressHandler_SmallBody_NotCompressed(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/tiny", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty for a tiny body", got)
	}
	raw := readRaw(t, resp)
	if string(raw) != "ok" {
		t.Fatalf("body = %q, want %q", raw, "ok")
	}
}

// Test_CompressHandler_Zstd_NegotiatedWhenOffered covers gzhttp's zstd
// support, kept on per CompressHandler's doc comment: a client whose
// Accept-Encoding lists zstd alongside other encodings a browser would
// realistically send gets zstd back, not gzip.
func Test_CompressHandler_Zstd_NegotiatedWhenOffered(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/big", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd", got)
	}

	raw := readRaw(t, resp)
	zr, err := zstd.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("zstd.NewReader: %v", err)
	}
	defer zr.Close()
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("zstd read: %v", err)
	}
	if !bytes.Equal(got, bigJSONBody) {
		t.Fatalf("decompressed body mismatch: got %d bytes, want %d bytes", len(got), len(bigJSONBody))
	}
}

// Test_CompressHandler_HeadRequest_NoContentEncoding covers HEAD: gzhttp
// disables compression for HEAD requests outright (there is no body to
// compress), so Content-Encoding must be absent even though the same
// route's GET response would be compressed.
func Test_CompressHandler_HeadRequest_NoContentEncoding(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodHead, srv.URL+"/big", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty for a HEAD response", got)
	}
	raw := readRaw(t, resp)
	if len(raw) != 0 {
		t.Fatalf("HEAD response body = %d bytes, want 0", len(raw))
	}
}

// Test_CompressHandler_PartialContent_PassedThroughIdentical covers a 206
// + Content-Range response (a byte-range reply): gzhttp must leave it
// completely untouched — Content-Encoding must stay unset and the body
// must reach the client byte-identical.
func Test_CompressHandler_PartialContent_PassedThroughIdentical(t *testing.T) {
	srv := newMuxServer(t)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ranged", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty (Content-Range responses are never compressed)", got)
	}

	raw := readRaw(t, resp)
	if !bytes.Equal(raw, bigJSONBody) {
		t.Fatalf("body mismatch: got %d bytes, want %d bytes identical to source", len(raw), len(bigJSONBody))
	}
}

// Test_CompressHandler_304_NoBody proves the
// composed wrapper (gzhttp + contentLengthGuard) does not mistake a 304's
// echoed Content-Length for a body the handler owed but didn't write.
func Test_CompressHandler_304_NoBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/cached", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "12345")
		w.WriteHeader(http.StatusNotModified)
	})
	srv := httptest.NewServer(btpingo.CompressHandler(mux))
	t.Cleanup(srv.Close)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/cached", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", resp.StatusCode)
	}
	raw := readRaw(t, resp)
	if len(raw) != 0 {
		t.Fatalf("304 body = %d bytes, want 0", len(raw))
	}
}

// Test_CompressHandler_1xxThen200 proves a handler sending a 1xx
// informational response before its real 200 still ends up compressed
// and correct through the full wrapper.
func Test_CompressHandler_1xxThen200(t *testing.T) {
	full := strings.Repeat("hint-then-real-body-", 100) // above MinSize
	mux := http.NewServeMux()
	mux.HandleFunc("/hinted", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, full)
	})
	srv := httptest.NewServer(btpingo.CompressHandler(mux))
	t.Cleanup(srv.Close)
	client := noAutoDecompressClient(srv)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/hinted", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (final status, not the 103)", resp.StatusCode)
	}
	raw := readRaw(t, resp)
	var body []byte
	if resp.Header.Get("Content-Encoding") == gzipEncoding {
		body = gunzip(t, raw)
	} else {
		body = raw
	}
	if string(body) != full {
		t.Fatalf("body mismatch after 1xx-then-200, len got=%d want=%d", len(body), len(full))
	}
}

// Test_CompressHandler_TruncatedHandler_AbortsInsteadOfCleanEOF wires the
// exact production Handler (btpingo.CompressHandler) and proves the guard
// composes with gzhttp the way the truncation fix intends: a handler that
// announces Content-Length N but writes fewer bytes before returning must
// NOT reach the client as a clean, fully-decodable compressed response —
// the request must fail instead (a broken connection / unexpected EOF),
// both with and without Accept-Encoding.
func Test_CompressHandler_TruncatedHandler_AbortsInsteadOfCleanEOF(t *testing.T) {
	full := []byte(strings.Repeat("x", 4096))
	half := full[:len(full)/2]

	newHandler := func() http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(len(full)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(half)
		}
	}

	for _, tc := range []struct {
		name           string
		acceptEncoding string
	}{
		{"with Accept-Encoding gzip", "gzip"},
		{"without Accept-Encoding", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/truncated", newHandler())
			srv := httptest.NewServer(btpingo.CompressHandler(mux))
			t.Cleanup(srv.Close)
			client := noAutoDecompressClient(srv)

			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/truncated", nil)
			if tc.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tc.acceptEncoding)
			}
			resp, err := client.Do(req)
			if err != nil {
				// The connection was aborted before headers/trailer
				// completed — an acceptable failure shape too.
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if _, err := io.ReadAll(resp.Body); err == nil {
				t.Fatalf("expected a read error (truncated/aborted response), got a clean read")
			}
		})
	}
}

// Test_CompressHandler_OverlongHandler_AbortsInsteadOfExtraBytes wires the
// exact production Handler and proves the other half of the truncation
// fix: a handler that announces a Content-Length and then writes MORE
// bytes than that before returning must not reach the client as a clean,
// longer compressed response.
func Test_CompressHandler_OverlongHandler_AbortsInsteadOfExtraBytes(t *testing.T) {
	const declared = 4096
	overlong := []byte(strings.Repeat("x", declared+100))

	newOverlongHandler := func() http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(declared))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(overlong)
		}
	}

	t.Run("with Accept-Encoding gzip", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/overlong", newOverlongHandler())
		srv := httptest.NewServer(btpingo.CompressHandler(mux))
		t.Cleanup(srv.Close)
		client := noAutoDecompressClient(srv)

		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/overlong", nil)
		req.Header.Set("Accept-Encoding", gzipEncoding)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if body, err := io.ReadAll(resp.Body); err == nil {
			t.Fatalf("expected a read/decode error for an overlong compressed response, got a clean %d-byte read", len(body))
		}
	})

	// Without Accept-Encoding, gzhttp never starts compressing, so
	// nothing about this guard should change what a plain net/http
	// server running the exact same handler (no guard, no gzhttp) would
	// do with an overlong write.
	t.Run("without Accept-Encoding", func(t *testing.T) {
		plainTS := httptest.NewServer(newOverlongHandler())
		t.Cleanup(plainTS.Close)
		plainResp, plainErr := plainTS.Client().Get(plainTS.URL)
		var plainBody []byte
		var plainReadErr error
		if plainErr == nil {
			defer func() { _ = plainResp.Body.Close() }()
			plainBody, plainReadErr = io.ReadAll(plainResp.Body)
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/overlong", newOverlongHandler())
		srv := httptest.NewServer(btpingo.CompressHandler(mux))
		t.Cleanup(srv.Close)
		resp, err := noAutoDecompressClient(srv).Get(srv.URL + "/overlong")
		var body []byte
		var readErr error
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			body, readErr = io.ReadAll(resp.Body)
		}

		plainFailed := plainErr != nil || plainReadErr != nil
		gotFailed := err != nil || readErr != nil
		if plainFailed != gotFailed {
			t.Fatalf("outcome differs from plain net/http: plain failed=%v (err=%v, readErr=%v), production wiring failed=%v (err=%v, readErr=%v)",
				plainFailed, plainErr, plainReadErr, gotFailed, err, readErr)
		}
		if !plainFailed && !bytes.Equal(plainBody, body) {
			t.Fatalf("body differs from plain net/http: plain = %d bytes, production wiring = %d bytes", len(plainBody), len(body))
		}
	})
}

// Test_CompressHandler_NoWriteHandler_AbortsInsteadOfCleanEmptyResponse
// wires the exact production Handler for the gap the implicit-200 latch
// closes: a handler that sets a non-zero Content-Length and then returns
// without ever calling Write or WriteHeader. net/http (and gzhttp above
// it) would otherwise commit a clean, empty 200 for that declared
// length — the client must see an error/EOF instead, exactly like the
// already-covered explicit truncation case.
func Test_CompressHandler_NoWriteHandler_AbortsInsteadOfCleanEmptyResponse(t *testing.T) {
	const declared = 4096

	newNoWriteHandler := func() http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(declared))
			// deliberately no Write, no WriteHeader
		}
	}

	for _, tc := range []struct {
		name           string
		acceptEncoding string
	}{
		{"with Accept-Encoding gzip", gzipEncoding},
		{"without Accept-Encoding", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/nowrite", newNoWriteHandler())
			srv := httptest.NewServer(btpingo.CompressHandler(mux))
			t.Cleanup(srv.Close)
			client := noAutoDecompressClient(srv)

			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/nowrite", nil)
			if tc.acceptEncoding != "" {
				req.Header.Set("Accept-Encoding", tc.acceptEncoding)
			}
			resp, err := client.Do(req)
			if err != nil {
				// The connection was aborted before headers/trailer
				// completed — an acceptable failure shape too.
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if body, err := io.ReadAll(resp.Body); err == nil {
				t.Fatalf("expected a read error (aborted zero-byte-vs-declared-length response), got a clean %d-byte read", len(body))
			}
		})
	}
}

// Test_CompressHandler_Hijack_Works proves a websocket-upgrade-style
// handler that hijacks the connection still works through the full
// CompressHandler wrapper, both with and without Accept-Encoding (gzhttp
// picks a different writer for each).
func Test_CompressHandler_Hijack_Works(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hijack", func(w http.ResponseWriter, _ *http.Request) {
		// Direct assertion, as gin's c.Writer.Hijack() does:
		// http.NewResponseController would fall back through Unwrap and
		// hide a missing clGuardWriter.Hijack.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "ResponseWriter does not implement http.Hijacker", http.StatusInternalServerError)
			return
		}
		conn, bw, err := hj.Hijack()
		if err != nil {
			http.Error(w, "hijack failed", http.StatusInternalServerError)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = bw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nhijacked")
		_ = bw.Flush()
	})
	srv := httptest.NewServer(btpingo.CompressHandler(mux))
	t.Cleanup(srv.Close)

	for _, ae := range []string{"", gzipEncoding} {
		t.Run("Accept-Encoding="+ae, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/hijack", nil)
			if ae != "" {
				req.Header.Set("Accept-Encoding", ae)
			}
			resp, err := noAutoDecompressClient(srv).Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if string(got) != "hijacked" {
				t.Fatalf("body = %q, want %q", got, "hijacked")
			}
		})
	}
}

// Test_CompressHandler_CloseNotify_Works proves a handler that type
// -asserts http.CloseNotifier on the ResponseWriter it receives still
// gets a working channel through the full CompressHandler wrapper, even
// when gzhttp picks its pass-through writer (no Accept-Encoding), which
// does not itself implement CloseNotifier.
//
// http.CloseNotifier itself is deprecated in favour of Request.Context,
// but clGuardWriter implements it because some frameworks (e.g. gin's
// c.Stream) still call it through an unchecked type assertion — the
// nolint below is for that deliberate, still-required use, not an
// endorsement of new code using it.
func Test_CompressHandler_CloseNotify_Works(t *testing.T) {
	started := make(chan struct{})
	notified := make(chan bool, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/notify", func(w http.ResponseWriter, r *http.Request) {
		cn, ok := w.(http.CloseNotifier) //nolint:staticcheck // deliberately testing the deprecated interface clGuardWriter still implements
		if !ok {
			http.Error(w, "ResponseWriter does not implement CloseNotifier", http.StatusInternalServerError)
			return
		}
		close(started)
		select {
		case <-cn.CloseNotify():
			notified <- true
		case <-time.After(5 * time.Second):
			notified <- false
		}
	})
	srv := httptest.NewServer(btpingo.CompressHandler(mux))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/notify", nil)
	go func() {
		<-started
		cancel() // client-side cancellation closes the connection
	}()
	//nolint:bodyclose // the request is expected to fail once cancelled
	_, _ = srv.Client().Do(req)

	select {
	case got := <-notified:
		if !got {
			t.Fatalf("CloseNotify channel never fired within the timeout")
		}
	case <-time.After(6 * time.Second):
		t.Fatalf("handler never observed the client disconnect")
	}
}

// Test_CompressHandler_GzipFlush_DeliversIncrementally is
// Test_clGuardWriter_Flush_DeliversIncrementally's companion through the
// full CompressHandler wrapper with Accept-Encoding: gzip, proving gzhttp
// itself flushes compressed data onto the connection rather than buffering
// it until the handler returns: the first event must decode while the
// handler is still blocked, not only afterwards.
func Test_CompressHandler_GzipFlush_DeliversIncrementally(t *testing.T) {
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/gzip-stream", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(30 * time.Second):
		}
		_, _ = io.WriteString(w, "data: second\n\n")
	})
	srv := httptest.NewServer(btpingo.CompressHandler(mux))
	t.Cleanup(srv.Close)
	defer close(release)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/gzip-stream", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)

	first := make(chan string, 1)
	go func() {
		resp, err := noAutoDecompressClient(srv).Do(req)
		if err != nil {
			first <- "error: " + err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.Header.Get("Content-Encoding") != gzipEncoding {
			first <- "error: response was not gzip-encoded"
			return
		}
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			first <- "error: gzip.NewReader: " + err.Error()
			return
		}
		s := bufio.NewScanner(zr)
		if !s.Scan() {
			first <- "no line"
			return
		}
		first <- s.Text()
	}()
	select {
	case got := <-first:
		if got != "data: first" {
			t.Fatalf("first line = %q, want %q", got, "data: first")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first event not delivered while the handler was still running; gzhttp's Flush did not reach the connection")
	}
}

// Test_CompressHandler_Unwrap_SetWriteDeadlineWorks proves
// clGuardWriter's Unwrap method lets http.ResponseController reach
// through to the real connection's deadline controls, both with and
// without gzhttp actively compressing.
func Test_CompressHandler_Unwrap_SetWriteDeadlineWorks(t *testing.T) {
	for _, ae := range []string{"", gzipEncoding} {
		t.Run("Accept-Encoding="+ae, func(t *testing.T) {
			result := make(chan error, 1)
			mux := http.NewServeMux()
			mux.HandleFunc("/deadline", func(w http.ResponseWriter, _ *http.Request) {
				err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
				result <- err
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, strings.Repeat("z", 2000))
			})
			srv := httptest.NewServer(btpingo.CompressHandler(mux))
			t.Cleanup(srv.Close)

			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/deadline", nil)
			if ae != "" {
				req.Header.Set("Accept-Encoding", ae)
			}
			resp, err := noAutoDecompressClient(srv).Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if _, err := io.ReadAll(resp.Body); err != nil {
				t.Fatalf("read body: %v", err)
			}

			if err := <-result; err != nil {
				t.Fatalf("SetWriteDeadline via ResponseController failed: %v", err)
			}
		})
	}
}

// Test_CompressHandler_SSE_Flush_Works proves an SSE-style streaming
// handler that flushes incrementally still delivers its chunks through
// the full CompressHandler wrapper (no Content-Length is ever set, so
// gzhttp streams and the guard's "want" stays -1).
func Test_CompressHandler_SSE_Flush_Works(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stream", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			panic("ResponseWriter passed to handler does not implement http.Flusher")
		}
		for range 3 {
			_, _ = io.WriteString(w, "data: x\n\n")
			flusher.Flush()
		}
	})
	srv := httptest.NewServer(btpingo.CompressHandler(mux))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/stream", nil)
	req.Header.Set("Accept-Encoding", gzipEncoding)
	resp, err := noAutoDecompressClient(srv).Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == gzipEncoding {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			t.Fatalf("gzip.NewReader: %v", err)
		}
		body = zr
	}
	scanner := bufio.NewScanner(body)
	chunks := 0
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data:") {
			chunks++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if chunks != 3 {
		t.Fatalf("got %d SSE chunks, want 3", chunks)
	}
}
