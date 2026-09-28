package btpingo_test

import (
	"context"
	"testing"

	"github.com/corbym/gocrest/is"
	"github.com/corbym/gocrest/then"

	"github.com/hochfrequenz/btpingo"
)

// Test_ScopesFromContext_EmptyWithoutMiddleware is the fail-closed
// property, and it is the one that matters: a handler asking about a
// scope on a request that never passed JWTValidator.Middleware must be
// told "no", never "unknown". HasScope is what a huma operation uses to
// REPORT a capability (e.g. a "may read data" flag), so a nil-means-yes
// reading would advertise content on an unauthenticated request.
func Test_ScopesFromContext_EmptyWithoutMiddleware(t *testing.T) {
	ctx := context.Background()

	then.AssertThat(t, len(btpingo.ScopesFromContext(ctx)), is.EqualTo(0))
	then.AssertThat(t, btpingo.HasScope(ctx, "myapp!t1234.ReadData"), is.False())
}

func Test_ScopesFromContext_RoundTrips(t *testing.T) {
	ctx := btpingo.ContextWithScopes(context.Background(),
		[]string{"myapp!t1234.User", "myapp!t1234.ReadData"})

	then.AssertThat(t, len(btpingo.ScopesFromContext(ctx)), is.EqualTo(2))
	then.AssertThat(t, btpingo.HasScope(ctx, "myapp!t1234.ReadData"), is.True())
	then.AssertThat(t, btpingo.HasScope(ctx, "myapp!t1234.User"), is.True())
}

// Test_HasScope_IsExactNotPrefix mirrors RequireScope's own rule: XSUAA
// scopes are qualified strings, and a prefix or substring match would
// grant "…ReadData" to a holder of "…ReadDataPreview".
func Test_HasScope_IsExactNotPrefix(t *testing.T) {
	ctx := btpingo.ContextWithScopes(context.Background(),
		[]string{"myapp!t1234.ReadDataPreview", "other!t1.ReadData"})

	then.AssertThat(t, btpingo.HasScope(ctx, "myapp!t1234.ReadData"), is.False())
	then.AssertThat(t, btpingo.HasScope(ctx, "ReadData"), is.False())
	then.AssertThat(t, btpingo.HasScope(ctx, ""), is.False())
}

// Test_ScopesFromContext_IgnoresAForeignValue: the key is unexported, so
// nothing outside btpingo can plant a value under it — but a wrong-typed
// value must still read as "no scopes" rather than panic.
func Test_ScopesFromContext_SurvivesAnUnrelatedContext(t *testing.T) {
	type otherKey struct{}
	ctx := context.WithValue(context.Background(), otherKey{}, []string{"myapp!t1234.ReadData"})

	then.AssertThat(t, btpingo.HasScope(ctx, "myapp!t1234.ReadData"), is.False())
}
