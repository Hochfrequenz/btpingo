package ginpingo_test

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hochfrequenz/btpingo"
	"github.com/hochfrequenz/btpingo/ginpingo"
)

// Example wires the package the way the README's quick start does. It
// has no Output comment, so `go test` compiles it but does not run it:
// it needs a real Cloud Foundry environment.
func Example() {
	ctx := context.Background()
	env, err := btpingo.LoadEnv() // VCAP_SERVICES: xsuaa, destination, connectivity
	if err != nil {
		log.Fatal(err)
	}
	svc, err := btpingo.NewService(env, btpingo.WithUserAgent("my-service/1.0"))
	if err != nil {
		log.Fatal(err)
	}
	validator, err := btpingo.NewJWTValidator(ctx, env.XSUAA)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.New()
	r.Use(ginpingo.RequestID())
	api := r.Group("/api", ginpingo.JWT(validator))
	api.GET("/ping", func(c *gin.Context) {
		resp, err := svc.CallOnPremise(c.Request.Context(), "MY_SAP_DESTINATION",
			http.MethodGet, "/sap/bc/ping?sap-client=100", nil, nil)
		if err != nil {
			ginpingo.AbortError(c, http.StatusBadGateway, btpingo.CodeUpstreamUnreachable,
				"on-premise system unreachable", err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		c.Status(resp.StatusCode)
	})
	_ = r
}
