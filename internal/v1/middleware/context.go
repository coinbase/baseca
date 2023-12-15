package middleware

import (
	"context"

	"github.com/coinbase/baseca/internal/types"
	"github.com/gogo/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

func (m *Middleware) SetAuthenticationContext(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Internal, "failed to retrieve metadata from context")
	}

	if auth, ok := types.Methods[info.FullMethod]; ok {
		// Service Account UUID
		if auth == types.ServiceAuthentication {
			clientIdAuthorizationHeader, ok := md[clientIdAuthorizationHeaderKey]
			if !ok {
				return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
			}
			ctx = context.WithValue(ctx, types.ServiceAuthenticationContextKey, clientIdAuthorizationHeader[0])
		}

		// Provisioner Account UUID
		if auth == types.ProvisionerAuthentication {
			clientIdAuthorizationHeader, ok := md[clientIdAuthorizationHeaderKey]
			if !ok {
				return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
			}
			ctx = context.WithValue(ctx, types.ProvisionerAuthenticationContextKey, clientIdAuthorizationHeader[0])
		}
	}
	return handler(ctx, req)
}
