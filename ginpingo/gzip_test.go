package ginpingo_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"
	"github.com/gin-gonic/gin"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/ginpingo"
	"github.com/hochfrequenz/btpingo/internal/testkit"
)

// bigPayload is well over ginpingo.DefaultGzipMinLength (1024 bytes)
// so tests that want compression to trigger don't have to reason
// about the threshold themselves.
func bigPayload() map[string]string {
	m := make(map[string]string, 64)
	for i := range 64 {
		m[fmt.Sprintf("field-%02d", i)] = strings.Repeat("x", 32)
	}
	return m
}

func mustGunzip(t *testing.T, data []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	then.AssertThat(t, err, is.Nil())
	out, err := io.ReadAll(zr)
	then.AssertThat(t, err, is.Nil())
	return out
}

func Test_Gzip_CompressesWhenAccepted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.Gzip())
	r.GET("/x", func(c *gin.Context) { c.JSON(http.StatusOK, bigPayload()) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo("gzip"))
	then.AssertThat(t, w.Header().Get("Vary"), is.EqualTo("Accept-Encoding"))
	// Mutation proof (no-stale-Content-Length): a middleware that
	// forgot to delete a pre-set/auto-computed Content-Length would
	// leave a value here that doesn't match the compressed body's
	// actual length.
	then.AssertThat(t, w.Header().Get("Content-Length"), is.EqualTo(""))

	var got map[string]string
	then.AssertThat(t, json.Unmarshal(mustGunzip(t, w.Body.Bytes()), &got), is.Nil())
	then.AssertThat(t, len(got), is.EqualTo(len(bigPayload())))
}

// Test_Gzip_DropsStaleContentLength exercises the case where the
// handler (via c.DataFromReader with a known length) announces a
// Content-Length before the middleware decides to compress. gin's
// render.Reader sets that header straight from the caller-supplied
// length, so it's a genuine pre-existing value the middleware must
// delete — unlike a Write-driven c.JSON response, whose Content-Length
// is never set at all and so can't tell a working Del() apart from a
// missing one.
func Test_Gzip_DropsStaleContentLength(t *testing.T) {
	gin.SetMode(gin.TestMode)
	payload := strings.Repeat("z", 4096)

	r := gin.New()
	r.Use(ginpingo.Gzip())
	r.GET("/x", func(c *gin.Context) {
		c.DataFromReader(http.StatusOK, int64(len(payload)), "text/plain", strings.NewReader(payload), nil)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo("gzip"))
	// Mutation proof: without startCompressing's Header().Del("Content-Length"),
	// this would still read "4096" — the pre-compression length gin's
	// render.Reader set — which no longer matches the compressed body
	// on the wire.
	then.AssertThat(t, w.Header().Get("Content-Length"), is.EqualTo(""))
	then.AssertThat(t, string(mustGunzip(t, w.Body.Bytes())), is.EqualTo(payload))
}

func Test_Gzip_NotCompressedWithoutAcceptEncoding(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.Gzip())
	r.GET("/x", func(c *gin.Context) { c.JSON(http.StatusOK, bigPayload()) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// No Accept-Encoding header at all.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo(""))
	var got map[string]string
	then.AssertThat(t, json.Unmarshal(w.Body.Bytes(), &got), is.Nil())
	then.AssertThat(t, len(got), is.EqualTo(len(bigPayload())))
}

func Test_Gzip_BelowMinNotCompressed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.Gzip()) // default 1 KiB minimum
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "tiny") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo(""))
	then.AssertThat(t, w.Body.String(), is.EqualTo("tiny"))
}

func Test_Gzip_PreEncodedPassthrough(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var pre bytes.Buffer
	zw := gzip.NewWriter(&pre)
	_, err := zw.Write([]byte(strings.Repeat("already-compressed-upstream ", 100)))
	then.AssertThat(t, err, is.Nil())
	then.AssertThat(t, zw.Close(), is.Nil())
	preBytes := pre.Bytes()

	r := gin.New()
	r.Use(ginpingo.Gzip())
	r.GET("/x", func(c *gin.Context) {
		c.Header("Content-Encoding", "gzip")
		c.Header("Content-Type", "application/octet-stream")
		c.Status(http.StatusOK)
		// Two separate writes (rather than a single c.Data call)
		// exercise both the writePending->passthrough handoff on the
		// first write and the already-decided passthrough branch of
		// Write on the second.
		half := len(preBytes) / 2
		_, err := c.Writer.Write(preBytes[:half])
		then.AssertThat(t, err, is.Nil())
		_, err = c.Writer.Write(preBytes[half:])
		then.AssertThat(t, err, is.Nil())
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo("gzip"))
	// Byte-identical: a single gunzip round-trip recovers the original
	// plaintext. Double-compression would still gunzip once, but the
	// result would be gzip-magic bytes, not the plaintext, and the
	// raw bytes on the wire would differ from preBytes.
	then.AssertThat(t, bytes.Equal(w.Body.Bytes(), preBytes), is.True())
	then.AssertThat(t, string(mustGunzip(t, w.Body.Bytes())), is.EqualTo(strings.Repeat("already-compressed-upstream ", 100)))
}

// Test_Gzip_FlushForcesDecision proves Flush does not just delegate to
// the underlying connection: it must commit the pending
// compress-or-passthrough decision immediately (mutation proof for
// "Flush must flush the gzip writer"). Both writes here total far
// less than DefaultGzipMinLength, so without Flush forcing the
// decision, the response would stay uncompressed until the handler
// returns — which would still happen to produce a correct body, just
// not a compressed one, so we assert on Content-Encoding directly
// rather than only on the decompressed content.
func Test_Gzip_FlushForcesDecision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.Gzip()) // default 1 KiB minimum; both chunks below it
	r.GET("/x", func(c *gin.Context) {
		c.Status(http.StatusOK)
		_, err := c.Writer.Write([]byte("small-chunk"))
		then.AssertThat(t, err, is.Nil())
		c.Writer.Flush() // forces the compress decision now
		_, err = c.Writer.Write([]byte("-more"))
		then.AssertThat(t, err, is.Nil())
		c.Writer.Flush() // second Flush: already compressing
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo("gzip"))
	then.AssertThat(t, string(mustGunzip(t, w.Body.Bytes())), is.EqualTo("small-chunk-more"))
}

// Test_Gzip_FlushOnPassthroughDelegates covers the Flush branch taken
// once a response has already been decided as passthrough (an
// existing Content-Encoding), which must simply flush the underlying
// connection without touching a (nonexistent) gzip stream.
func Test_Gzip_FlushOnPassthroughDelegates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.Gzip())
	r.GET("/x", func(c *gin.Context) {
		c.Header("Content-Encoding", "gzip")
		c.Status(http.StatusOK)
		_, err := c.Writer.Write([]byte("raw"))
		then.AssertThat(t, err, is.Nil())
		c.Writer.Flush()
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Body.String(), is.EqualTo("raw"))
}

// Test_Gzip_AcceptEncodingVariants covers acceptsGzip's comma-list and
// quality-value parsing beyond the plain "gzip" case already used
// elsewhere.
func Test_Gzip_AcceptEncodingVariants(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name           string
		acceptEncoding string
		wantCompressed bool
	}{
		{"other codings only", "deflate, br", false},
		{"quality zero rejects gzip", "gzip;q=0, deflate", false},
		{"gzip among several codings", "deflate, gzip, br", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(ginpingo.Gzip())
			r.GET("/x", func(c *gin.Context) { c.JSON(http.StatusOK, bigPayload()) })

			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Accept-Encoding", tc.acceptEncoding)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if tc.wantCompressed {
				then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo("gzip"))
			} else {
				then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo(""))
			}
		})
	}
}

// Test_Gzip_BodylessStatusNeverCompressed covers mustPassthrough's
// body-less-status branch (204/304): even if a handler writes bytes
// after such a status (unusual, but not impossible via a raw
// c.Writer.Write), the middleware must not gzip-wrap them.
func Test_Gzip_BodylessStatusNeverCompressed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.Gzip(ginpingo.WithGzipMinLength(0)))
	r.GET("/x", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
		// http.ErrBodyNotAllowed is expected here (net/http, and
		// httptest's ResponseRecorder, both reject a body after 204) —
		// the point of this test is that ginpingo's own gzip logic
		// still ran (and chose passthrough) before that rejection.
		_, _ = c.Writer.Write([]byte("ignored-by-real-clients"))
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo(""))
}

func Test_Gzip_AbortErrorStillValidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ginpingo.RequestID())
	r.Use(ginpingo.Gzip(ginpingo.WithGzipMinLength(0))) // force compression even for a small envelope
	r.GET("/x", func(c *gin.Context) {
		ginpingo.AbortError(c, http.StatusBadGateway, btpingo.CodeUpstreamUnreachable, "on-premise call failed", nil)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusBadGateway))
	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo("gzip"))

	var env btpingo.ErrorEnvelope
	// Mutation proof (finish() must Close the gzip writer): if the
	// trailing gzip footer is never written, gzip.NewReader/ReadAll
	// above fails with io.ErrUnexpectedEOF and this Unmarshal never
	// runs with valid bytes.
	then.AssertThat(t, json.Unmarshal(mustGunzip(t, w.Body.Bytes()), &env), is.Nil())
	then.AssertThat(t, string(env.Error.Code), is.EqualTo(string(btpingo.CodeUpstreamUnreachable)))
}

// Test_Gzip_StreamsBeforePipeCloses proves the middleware does not
// buffer a c.DataFromReader response until the handler finishes: it
// reads compressed bytes back off a real network connection while the
// io.Pipe feeding the handler is still open (its writer end has not
// been closed), then closes the pipe to let the handler finish.
func Test_Gzip_StreamsBeforePipeCloses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pr, pw := io.Pipe()

	r := gin.New()
	// minLength 0: a streaming response has no known total size, so
	// the middleware must not hold the first chunk back waiting for a
	// threshold that may never be reached.
	r.Use(ginpingo.Gzip(ginpingo.WithGzipMinLength(0)))
	r.GET("/stream", func(c *gin.Context) {
		c.DataFromReader(http.StatusOK, -1, "application/octet-stream", pr, nil)
	})

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/stream", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	// Write the first chunk concurrently with the request above: the
	// server only flushes response headers once the handler's first
	// io.Copy read from pr succeeds, so waiting for resp before
	// writing here would deadlock (headers wait on this write, this
	// write waits on the handler's read, which only happens once the
	// request is being served).
	first := strings.Repeat("stream-chunk ", 50) // > 0 bytes, well below any buffering
	writeErrCh := make(chan error, 1)
	go func() {
		_, err := pw.Write([]byte(first))
		writeErrCh <- err
	}()

	var resp *http.Response
	select {
	case resp = <-respCh:
	case err := <-errCh:
		t.Fatalf("request failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("request did not even get response headers within 5s")
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	then.AssertThat(t, resp.Header.Get("Content-Encoding"), is.EqualTo("gzip"))

	select {
	case err := <-writeErrCh:
		then.AssertThat(t, err, is.Nil())
	case <-time.After(5 * time.Second):
		t.Fatal("first chunk write to the pipe never completed")
	}

	// Read the decompressed first chunk off the wire without closing
	// the pipe writer. If the middleware buffered instead of
	// flushing, this read blocks until it times out (mutation proof
	// for "flush the gzip writer + the connection on every write
	// while compressing").
	zr, err := gzip.NewReader(resp.Body)
	then.AssertThat(t, err, is.Nil())
	br := bufio.NewReader(zr)
	got := make([]byte, len(first))

	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(br, got)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		then.AssertThat(t, err, is.Nil())
	case <-time.After(3 * time.Second):
		t.Fatal("did not receive the first chunk before the pipe writer closed: streaming is broken")
	}
	then.AssertThat(t, string(got), is.EqualTo(first))

	then.AssertThat(t, pw.Close(), is.Nil())
}

func Test_Gzip_ProxyHandler_UpstreamGzipNotDoubleCompressed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	plain := strings.Repeat("sap-already-gzipped-this ", 200)

	s := testkit.NewBTPStack(t, "placeholder")
	s = testkit.NewBTPStack(t, fmt.Sprintf(`{
		"destinationConfiguration":{"Name":"D","Type":"HTTP","URL":%q,"Authentication":"NoAuthentication","ProxyType":"OnPremise"}
	}`, s.OnPrem.URL))

	// Replace OnPrem with a server that answers as SAP would once
	// Go's Transport has already decoded nothing (Accept-Encoding was
	// forwarded, so SAP gzip-encodes and Content-Encoding survives the
	// hop, per proxy.go's fwdheader.Skip / callOnce header copy).
	s.OnPrem = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(plain))
		_ = zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(s.OnPrem.Close)

	svc, err := btpingo.NewService(s.Env)
	then.AssertThat(t, err, is.Nil())

	r := gin.New()
	r.Use(ginpingo.Gzip(ginpingo.WithGzipMinLength(0)))
	r.Any("/api/sap/:destination/*path", ginpingo.ProxyHandler(svc))

	req := httptest.NewRequest(http.MethodGet, "/api/sap/D/whatever", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	then.AssertThat(t, w.Code, is.EqualTo(http.StatusOK))
	then.AssertThat(t, w.Header().Get("Content-Encoding"), is.EqualTo("gzip"))
	// Mutation proof: if mustPassthrough's existing-Content-Encoding
	// check is removed, this body is gzip-of-gzip — a single gunzip
	// pass would yield gzip magic bytes instead of plain, and
	// string(...) would not equal plain.
	then.AssertThat(t, string(mustGunzip(t, w.Body.Bytes())), is.EqualTo(plain))
}
