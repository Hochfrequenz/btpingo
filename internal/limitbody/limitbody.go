// Package limitbody holds the response-body size cap shared by
// btpingo.Service and btpingotest.HandlerCaller, so both enforce the
// limit with the same code. It is internal because the sentinel error
// belongs to package btpingo and is handed in by the caller.
package limitbody

import "io"

type body struct {
	rc      io.ReadCloser
	limit   int64
	read    int64
	errOver error
}

// New wraps rc so that reads up to limit bytes pass through unchanged
// and the (limit+1)-th byte triggers errOver from Read.
// The wrapper caps the per-Read slice so callers buffering the body
// (io.ReadAll) cannot grow the buffer past limit before hitting the
// error: the memory invariant the cap exists for.
func New(rc io.ReadCloser, limit int64, errOver error) io.ReadCloser {
	return &body{rc: rc, limit: limit, errOver: errOver}
}

func (b *body) Read(p []byte) (int, error) {
	if b.read > b.limit {
		return 0, b.errOver
	}
	// Cap the slice so we read at most one byte past the limit: that is
	// what proves the body has more than `limit` content. Without this
	// cap a single Read of e.g. 32 KiB into a 1-byte-remaining budget
	// would buffer 32 KiB before the error fires.
	remaining := b.limit - b.read + 1
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := b.rc.Read(p)
	b.read += int64(n)
	if b.read > b.limit {
		return n, b.errOver
	}
	return n, err
}

func (b *body) Close() error { return b.rc.Close() }
