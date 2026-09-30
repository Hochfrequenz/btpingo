package btpingo

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/klauspost/compress/gzhttp"
)

// CompressHandler wraps h with response compression at the net/http
// level, plus a Content-Length guard that closes a truncation/overflow
// gap compression would otherwise introduce (see contentLengthGuard).
//
// A response is compressed with zstd or gzip only when the request's
// Accept-Encoding accepts one of them by q-value (zstd is preferred when
// both are equally acceptable — gzhttp's PreferZstd default). A request
// with no Accept-Encoding header, one that excludes both (e.g.
// "gzip;q=0, zstd;q=0"), or a response body under gzhttp's minimum size
// or of a skip-listed content type is sent uncompressed instead.
//
// Because it operates on plain http.Handler/http.ResponseWriter, it works
// the same whether the wrapped handler is a *gin.Engine, a huma mux, or an
// http.ServeMux — and it keeps this package gin-free.
//
// If the wrapped handler writes a different number of body bytes than
// the Content-Length it declared, CompressHandler logs one line at Error
// level on the default slog logger and aborts the connection with
// panic(http.ErrAbortHandler), so the client sees an unexpected EOF
// instead of a clean short or overlong response. A recover middleware
// placed around CompressHandler must re-panic http.ErrAbortHandler.
//
// Usage:
//
//	srv.Handler = btpingo.CompressHandler(router)
//
// gzhttp's own defaults are kept as-is, including its zstd support (not
// restricted to gzip-only): a client that never advertises "zstd" simply
// gets gzip, and a client that does gets real additional bandwidth
// savings. An SAP approuter placed in front of a service passes a
// backend's Content-Encoding through unchanged rather than stripping or
// re-encoding it (checked at @sap/approuter 23.0.0), so compressing here
// is safe even when an approuter sits between the caller and this
// service. gzhttp also keeps its own minimum-size threshold and
// content-type skip list, so small bodies and already-compressed
// upstream responses are left alone rather than being (re-)compressed.
func CompressHandler(h http.Handler) http.Handler {
	return gzhttp.GzipHandler(contentLengthGuard(h))
}

// contentLengthGuard sits between gzhttp and the wrapped handler and
// closes a Content-Length mismatch gap gzhttp does not cover on its own,
// in either direction:
//
//   - Short: a handler announces a Content-Length and then writes fewer
//     bytes than that before returning — e.g. a proxied on-prem response
//     whose connection drops mid-copy. gzhttp still frames a
//     syntactically complete gzip/zstd stream around whatever partial
//     bytes it saw and closes it cleanly. The client then sees a valid,
//     fully-decodable 200 response that is silently short.
//   - Overlong: a handler keeps writing past its own declared
//     Content-Length. net/http's own ErrContentLength enforcement only
//     fires when a Content-Length header is actually on the wire to the
//     client, but gzhttp removes that header the moment it starts
//     compressing — so with compression active, the extra bytes are
//     framed straight into the compressed stream and reach the client as
//     a clean response containing more than the handler declared.
//
// Both are the exact failure mode compression must not introduce: an
// uncompressed response in the same situation reaches the client as a
// broken connection (unexpected EOF), not a clean 200.
//
// The guard tracks the announced Content-Length and the bytes actually
// written; if the handler returns having written a different number of
// bytes than it declared — fewer or more — it panics with
// http.ErrAbortHandler. net/http's server recovers that panic itself,
// logs nothing (by design — it is the documented "silently abort"
// signal), and closes the connection without writing a final
// chunk/frame terminator. That reproduces the same client-visible
// unexpected-EOF failure an uncompressed response of the same shape
// would have produced, instead of a clean-looking short or overlong
// body.
//
// clGuardWriter.Write also refuses to forward any bytes from a call that
// would exceed the declared length, so the extra bytes never reach
// gzhttp; this end-of-handler check is the backstop for both directions.
//
// HEAD requests are exempt: RFC 9110 requires the same Content-Length a
// GET would carry, but a HEAD handler never writes a body, so "written !=
// want" is expected and not a mismatch.
func contentLengthGuard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := &clGuardWriter{ResponseWriter: w, want: -1, ctx: r.Context()}
		h.ServeHTTP(g, r)
		if g.hijacked {
			// After a successful Hijack the handler owns the raw
			// connection directly; g.want/g.written no longer describe
			// what reached the client (the handler writes past this
			// wrapper entirely, as the Hijack test does), so the guard
			// must never inspect or act on them here. Skipping
			// unconditionally — not just when wroteHeader is false —
			// also covers a handler that set Content-Length and called
			// WriteHeader before hijacking: the guard must still never
			// panic on that connection.
			return
		}
		if !g.wroteHeader {
			// The handler returned having only set headers (e.g.
			// Content-Length) without ever calling Write or
			// WriteHeader. net/http commits an implicit 200 the moment
			// ServeHTTP returns, so latch it here the same way an
			// explicit WriteHeader(200) would, instead of leaving
			// g.want at -1 and letting a zero-byte short response pass
			// unnoticed.
			g.WriteHeader(http.StatusOK)
		}
		if r.Method != http.MethodHead && g.want >= 0 && g.written != g.want {
			// net/http logs nothing for ErrAbortHandler and the access log
			// still says 200, so this line is the operator's only signal.
			slog.ErrorContext(r.Context(), "response length differs from its Content-Length; aborting connection",
				"method", r.Method, "path", r.URL.Path, "content_length", g.want, "written", g.written)
			panic(http.ErrAbortHandler) // no terminating chunk -> client sees EOF, as without compression
		}
	})
}

// clGuardWriter wraps http.ResponseWriter to observe the Content-Length
// the handler declares (if any) and the number of body bytes it actually
// writes. It implements http.Flusher and Unwrap (for
// http.ResponseController, e.g. per-request SetWriteDeadline) so it is
// transparent to callers that type-assert those interfaces on the
// original writer.
type clGuardWriter struct {
	http.ResponseWriter
	want, written int64
	wroteHeader   bool
	hijacked      bool
	ctx           context.Context
}

// WriteHeader latches only on the FIRST call that actually finalizes the
// header. Per RFC 9110 §15.2, 1xx informational status codes (e.g. 103
// Early Hints) are not the final response status — a handler may call
// WriteHeader(103) and then still call WriteHeader(200) later. Latching
// on a 1xx would freeze "want" (or wroteHeader) before the real
// Content-Length is known, so 1xx codes are explicitly skipped here and
// do not set wroteHeader.
func (w *clGuardWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if !w.wroteHeader {
		w.wroteHeader = true
		bodyAllowed := code >= 200 && code != http.StatusNoContent && code != http.StatusNotModified
		if cl, err := strconv.ParseInt(w.Header().Get("Content-Length"), 10, 64); err == nil && bodyAllowed {
			w.want = cl
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write mirrors net/http's own response.write behaviour for an overlong
// response (net/http/server.go): once a call would push the running
// total past the declared Content-Length, NONE of that call's bytes are
// forwarded to the underlying writer — not even the portion that would
// still fit — and the call reports http.ErrContentLength instead. That
// keeps the guarantee "no more bytes than declared ever reach the
// client" true at the Write call itself, not just at the
// end-of-handler check in contentLengthGuard, so an overlong write can
// never be framed into a syntactically valid, longer response by gzhttp
// sitting above this writer.
//
// w.written still tracks the full length the handler attempted to
// write, not just what was actually forwarded: that is what lets
// contentLengthGuard's end-of-handler check ("written != want") still
// detect and abort an overlong response even though the excess bytes
// were never forwarded here. Without that distinction, a handler whose
// overlong call is entirely swallowed would leave written == want and
// the mismatch that caused it would go unreported.
func (w *clGuardWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.want >= 0 && w.written+int64(len(b)) > w.want {
		w.written += int64(len(b))
		return 0, http.ErrContentLength
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Flush mirrors Write's own implicit-header latch: a handler may stream a
// body via Flush alone (e.g. after setting Content-Length) without ever
// calling Write or WriteHeader itself, and without this the guard's
// end-of-handler check would still see wroteHeader == false and want ==
// -1, missing a short response the same way an unflushed, never-written
// handler does.
func (w *clGuardWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *clGuardWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack and CloseNotify exist because some frameworks (e.g. gin) call
// both through unchecked type assertions on the writer they wrap:
// without them, a websocket upgrade or a streaming handler that expects
// CloseNotify panics with "interface conversion" once wrapped by this
// guard.
func (w *clGuardWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, bw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		// From here the handler owns the raw connection; contentLengthGuard
		// must not run its end-of-handler Content-Length check against
		// this writer any more (see the g.hijacked check there).
		w.hijacked = true
	}
	return conn, bw, err
}

// CloseNotify is derived from the request context rather than delegated:
// gzhttp's pass-through writer (used when the client sent no
// Accept-Encoding) does not implement http.CloseNotifier either. The
// context is cancelled on client disconnect and when ServeHTTP returns,
// so the goroutine cannot outlive the request.
func (w *clGuardWriter) CloseNotify() <-chan bool {
	ch := make(chan bool, 1)
	go func() {
		<-w.ctx.Done()
		ch <- true
	}()
	return ch
}
