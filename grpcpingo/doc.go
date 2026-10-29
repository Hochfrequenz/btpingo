// Package grpcpingo is the gRPC / Connect counterpart of ginpingo: the JWT
// and scope check, the request-size limit and the error mapping of a btpingo
// service, for handlers built with connect-go (connectrpc.com/connect).
// connect-go serves gRPC, gRPC-Web and Connect from one handler, and the
// middleware here answers a rejected call in the protocol of the request.
//
// The middleware are plain net/http middleware, func(http.Handler)
// http.Handler, so they wrap a connect handler directly or sit in a gin route
// through gin.WrapH. [Auth] is built on connectrpc.com/authn.
package grpcpingo
