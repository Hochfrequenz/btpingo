package ginpingo

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// DefaultGzipMinLength is the response-size threshold below which Gzip
// skips compression. 1 KiB is small enough to catch typical JSON API
// payloads but large enough that the gzip header/footer overhead (~20
// bytes) plus the CPU cost of compressing a handful of bytes isn't
// wasted on trivial responses (an empty JSON array, a 204, a tiny
// status object).
const DefaultGzipMinLength = 1024

// GzipOption configures Gzip. The only knob today is the minimum
// response size; see WithGzipMinLength.
type GzipOption func(*gzipConfig)

type gzipConfig struct {
	minLength int
}

// WithGzipMinLength overrides DefaultGzipMinLength. Responses smaller
// than n bytes are written untouched even when the client accepts
// gzip — for a response streamed via c.DataFromReader with no known
// length, pass 0 (or a negative value) to compress from the first
// byte, since there's nothing to buffer safely while deciding.
func WithGzipMinLength(n int) GzipOption {
	return func(c *gzipConfig) { c.minLength = n }
}

// gzipWriterPool recycles *gzip.Writer values across requests.
// compress/gzip allocates a fair amount of internal state (the
// sliding window and Huffman tables); pooling avoids repeating that
// allocation on every compressed response. Writers are Reset before
// reuse and Reset(io.Discard) before being returned to the pool so
// the pool doesn't pin a reference to the last request's
// ResponseWriter (and the connection it wraps) between requests.
var gzipWriterPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

// Gzip is a Gin middleware that compresses the response body with
// gzip when the request's Accept-Encoding header allows it, and
// leaves the response untouched otherwise. Design points (from
// Hochfrequenz/btpingo#7), recorded here rather than left as TODOs:
//
//   - Dependency: implemented on stdlib compress/gzip plus a
//     sync.Pool, not github.com/gin-contrib/gzip. The behaviour list
//     that library provides (Vary, Content-Length removal, pass-
//     through of an existing Content-Encoding, Flush, a minimum
//     length, skipping bodies that shouldn't be touched) is
//     reproduced below in well under 200 lines; pulling in a whole
//     dependency for that is not a proportionate trade against one
//     more package for btpingo's consumers to vet and keep patched.
//   - Vary: Accept-Encoding is added unconditionally, for every
//     request this middleware sees — including ones that didn't ask
//     for gzip — because a shared cache in front of the service needs
//     to know the response could differ by that header for some
//     *other* request, not just this one.
//   - Content-Length is dropped the moment compression starts, since
//     the compressed length differs from whatever the handler
//     announced (or from Go's own automatic length computation for a
//     single-Write response); the connection falls back to chunked
//     transfer encoding, which every real HTTP client handles.
//   - A response that already carries a Content-Encoding header is
//     passed through byte-for-byte. This is not just a generic
//     safety net: ProxyHandler forwards the client's Accept-Encoding
//     to SAP unchanged, so on-premise responses SAP already gzipped
//     arrive with Content-Encoding: gzip already set and must not be
//     compressed again (see proxy.go and the issue's "Why" section).
//   - Streaming (c.DataFromReader, SSE-style handlers) keeps
//     streaming: gzipResponseWriter.Write flushes the gzip writer and
//     the underlying connection after every write once compression
//     has started, and an explicit Flush call forces the pending
//     decision (compress or pass through) immediately instead of
//     waiting for minLength bytes to accumulate, so a handler that
//     flushes early still gets bytes on the wire right away.
//   - HEAD requests and responses with no body (204, 304) are never
//     wrapped: there is nothing to compress and wrapping them would
//     only add Vary noise without benefit. (204/304 are additionally
//     guarded by gzipResponseWriter itself, in case a HEAD-like body-
//     less status is set through some other route.)
//   - The minimum length (WithGzipMinLength, default
//     DefaultGzipMinLength) is enforced by buffering up to that many
//     bytes before deciding; once the buffer reaches the threshold
//     (or Flush is called) the middleware commits to compressing and
//     never buffers again for that response.
func Gzip(opts ...GzipOption) gin.HandlerFunc {
	cfg := gzipConfig{minLength: DefaultGzipMinLength}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(c *gin.Context) {
		if !acceptsGzip(c.GetHeader("Accept-Encoding")) {
			c.Next()
			return
		}
		// The response may differ by Accept-Encoding for *some*
		// request even when this one didn't ask for gzip below (e.g.
		// it asked for identity, or another compression this
		// middleware doesn't implement) — but we've already returned
		// above for that case. This branch is the one where the
		// client did offer gzip, so set Vary before deciding whether
		// we actually use it (HEAD, or a body-less status set later,
		// still leave it correct: a cache must key on the header
		// regardless of what this particular response ends up
		// doing).
		c.Writer.Header().Add("Vary", "Accept-Encoding")

		if c.Request.Method == http.MethodHead {
			c.Next()
			return
		}

		gz, _ := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(c.Writer)
		gw := &gzipResponseWriter{ResponseWriter: c.Writer, gz: gz, minLength: cfg.minLength}
		c.Writer = gw

		c.Next()

		gw.finish()
		gz.Reset(io.Discard)
		gzipWriterPool.Put(gz)
	}
}

// acceptsGzip reports whether the Accept-Encoding header value
// permits the gzip coding. It handles the common "gzip",
// "gzip, deflate, br" and quality-value forms ("gzip;q=0") but does
// not implement full RFC 9110 precedence between codings — btpingo's
// callers are internal services and browsers, not clients that
// negotiate exotic Accept-Encoding combinations.
func acceptsGzip(header string) bool {
	if header == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		coding, params, _ := strings.Cut(part, ";")
		coding = strings.TrimSpace(coding)
		if !strings.EqualFold(coding, "gzip") {
			continue
		}
		if q, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if v, err := strconv.ParseFloat(q, 64); err == nil && v == 0 {
				continue
			}
		}
		return true
	}
	return false
}

// gzipWriterState tracks the pending/compressing/passthrough decision
// a gzipResponseWriter makes once, the first time it has enough
// information to make it, and never revisits.
type gzipWriterState int

const (
	gzipStatePending gzipWriterState = iota
	gzipStateCompressing
	gzipStatePassthrough
)

// gzipResponseWriter buffers up to minLength bytes of a response body
// while deciding whether to compress it, then either streams the rest
// through gz (flushing after every write, so a streaming handler's
// bytes reach the client without waiting for the response to finish)
// or writes the buffered-and-all-subsequent bytes straight through
// unmodified.
type gzipResponseWriter struct {
	gin.ResponseWriter
	gz         *gzip.Writer
	minLength  int
	buf        []byte
	state      gzipWriterState
	statusCode int
}

func (w *gzipResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// bodylessStatus reports whether code is a status Go's own net/http
// treats as never carrying a body (mirroring
// http.bodyAllowedForStatus, which is unexported).
func bodylessStatus(code int) bool {
	return (code >= 100 && code <= 199) || code == http.StatusNoContent || code == http.StatusNotModified
}

// mustPassthrough reports whether this response must never be
// touched: it already carries a Content-Encoding (typically an
// on-premise gzip body relayed by ProxyHandler) or its status code
// never carries a body in the first place.
func (w *gzipResponseWriter) mustPassthrough() bool {
	if w.Header().Get("Content-Encoding") != "" {
		return true
	}
	code := w.statusCode
	if code == 0 {
		code = http.StatusOK
	}
	return bodylessStatus(code)
}

func (w *gzipResponseWriter) startCompressing() {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", "gzip")
	w.state = gzipStateCompressing
}

func (w *gzipResponseWriter) Write(p []byte) (int, error) {
	switch w.state {
	case gzipStatePassthrough:
		return w.ResponseWriter.Write(p)
	case gzipStateCompressing:
		return w.writeCompressed(p)
	default: // gzipStatePending
		return w.writePending(p)
	}
}

func (w *gzipResponseWriter) writeCompressed(p []byte) (int, error) {
	n, err := w.gz.Write(p)
	if err != nil {
		return n, err
	}
	if err := w.gz.Flush(); err != nil {
		return n, err
	}
	w.ResponseWriter.Flush()
	return n, nil
}

func (w *gzipResponseWriter) writePending(p []byte) (int, error) {
	if w.mustPassthrough() {
		w.state = gzipStatePassthrough
		if len(w.buf) > 0 {
			if _, err := w.ResponseWriter.Write(w.buf); err != nil {
				w.buf = nil
				return 0, err
			}
			w.buf = nil
		}
		return w.ResponseWriter.Write(p)
	}

	w.buf = append(w.buf, p...)
	if len(w.buf) < w.minLength {
		return len(p), nil
	}
	w.startCompressing()
	buffered := w.buf
	w.buf = nil
	if _, err := w.writeCompressed(buffered); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *gzipResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// Flush forces the pending compress/passthrough decision immediately
// — regardless of how little has been buffered — and flushes
// whatever is ready to the underlying connection. This is what keeps
// c.DataFromReader / SSE-style handlers streaming: without it, a
// small first chunk would sit in w.buf until minLength bytes
// accumulated or the handler returned.
func (w *gzipResponseWriter) Flush() {
	if w.state == gzipStatePending {
		if w.mustPassthrough() {
			w.state = gzipStatePassthrough
			if len(w.buf) > 0 {
				_, _ = w.ResponseWriter.Write(w.buf)
				w.buf = nil
			}
		} else {
			w.startCompressing()
			if len(w.buf) > 0 {
				buffered := w.buf
				w.buf = nil
				_, _ = w.gz.Write(buffered)
			}
			_ = w.gz.Flush()
		}
	}
	w.ResponseWriter.Flush()
}

// finish is called once the handler chain has returned. A response
// still in gzipStatePending never reached minLength (or Flush), so
// whatever was buffered is the whole body — write it straight through
// uncompressed. A response in gzipStateCompressing needs its gzip
// writer closed to emit the trailing CRC/size footer.
func (w *gzipResponseWriter) finish() {
	switch w.state {
	case gzipStatePending:
		if len(w.buf) > 0 {
			_, _ = w.ResponseWriter.Write(w.buf)
			w.buf = nil
		}
	case gzipStateCompressing:
		_ = w.gz.Close()
	case gzipStatePassthrough:
		// Nothing buffered by definition — writePending flushes
		// through immediately once passthrough is decided.
	}
}
