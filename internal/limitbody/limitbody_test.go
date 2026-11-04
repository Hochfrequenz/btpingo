package limitbody_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo/internal/limitbody"
)

var errOver = errors.New("over")

func Test_Body_Limit(t *testing.T) {
	cases := []struct {
		name    string
		size    int
		limit   int64
		wantErr bool
	}{
		{"under", 5, 10, false},
		{"exactly at limit", 10, 10, false},
		{"one over", 11, 10, true},
		{"far over", 10000, 10, true},
		{"empty", 0, 10, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc := limitbody.New(io.NopCloser(strings.NewReader(strings.Repeat("x", c.size))), c.limit, errOver)
			b, err := io.ReadAll(rc)
			if c.wantErr {
				then.AssertThat(t, errors.Is(err, errOver), is.True())
				// never buffers more than limit+1 bytes
				then.AssertThat(t, int64(len(b)) <= c.limit+1, is.True())
				// sticky
				_, err = rc.Read(make([]byte, 1))
				then.AssertThat(t, errors.Is(err, errOver), is.True())
				return
			}
			then.AssertThat(t, err, is.Nil())
			then.AssertThat(t, len(b), is.EqualTo(c.size))
		})
	}
}

type closeSpy struct {
	io.Reader
	closed bool
}

func (c *closeSpy) Close() error { c.closed = true; return nil }

func Test_Body_CloseReachesUnderlying(t *testing.T) {
	spy := &closeSpy{Reader: strings.NewReader("x")}
	then.AssertThat(t, limitbody.New(spy, 1, errOver).Close(), is.Nil())
	then.AssertThat(t, spy.closed, is.True())
}
