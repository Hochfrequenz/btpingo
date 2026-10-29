package grpcpingo_test

import (
	"context"
	"log"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/grpcpingo"
)

// Example wires a connect service into a gin router behind Auth and MaxBodySize, and
// serves it with compression that leaves the RPC paths alone. It has no Output
// comment, so `go test` compiles it but does not run it: it needs a real Cloud
// Foundry environment. The handler stands in for generated code (NewXServiceHandler).
func Example() {
	env, err := btpingo.LoadEnv()
	if err != nil {
		log.Fatal(err)
	}
	validator, err := btpingo.NewJWTValidator(context.Background(), env.XSUAA)
	if err != nil {
		log.Fatal(err)
	}

	m := grpcpingo.Mapper{Domain: "myservice.example.com"}
	const limit = 1 << 20 // 1 MiB

	// With generated code: path, h := testv1connect.NewTestServiceHandler(impl, opts...)
	const path = "/test.v1.TestService/"
	h := connect.NewUnaryHandler(path+"Ping",
		func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithRecover(m.Recover),  // a panic becomes Internal with ErrorInfo
		connect.WithReadMaxBytes(limit), // limit for bodies without a Content-Length
	)

	// Auth first, then MaxBodySize: an unauthenticated caller learns nothing about the limit.
	guard := func(next http.Handler) http.Handler {
		return grpcpingo.Auth(validator, "myapp!t1.User", m)(grpcpingo.MaxBodySize(limit, m)(next))
	}

	r := gin.New()
	r.POST(path+"*rpc", gin.WrapH(guard(h)))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           btpingo.CompressHandlerSkipping(r, path), // gRPC clients reject an HTTP Content-Encoding
		ReadHeaderTimeout: 10 * time.Second,
	}
	_ = srv
}
