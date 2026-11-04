package pathsuffix_test

import (
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo/internal/pathsuffix"
)

func Test_Check(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"/a/b", false},
		{"a/b?x=1&y=2", false},
		{"/a/../b", true},
		{"..", true},
		{"/a/%2e%2e/b", true},
		{"/a%20b", true},
		{"/a..b", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			err := pathsuffix.Check(c.in)
			then.AssertThat(t, err != nil, is.EqualTo(c.wantErr))
		})
	}
}
