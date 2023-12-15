package middleware

import (
	"context"

	"github.com/coinbase/baseca/internal/lib/util"
	"github.com/coinbase/baseca/internal/types"
	"google.golang.org/grpc"
)

var (
	_default_queue = 1000
	ch             = make(chan context.Context, _default_queue)
	auth           = make(chan AuthenticationMetadata, _default_queue)
)

func (m *Middleware) ServerAuthenticationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var _authenticated bool
	var authentication types.AuthenticationKey
	var ok bool

	// User Authentication
	if authentication, ok = types.Methods[info.FullMethod]; !ok {
		userAccount := &UserAccount{
			middleware: m,
			info:       info,
		}
		payload, err := userAccount.Authenticate(ctx)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, types.UserAuthenticationContextKey, payload)
	}

	switch authentication {
	// Service Account Authentication
	case types.ServiceAuthentication:
		serviceAccount := &ServiceAccount{
			middleware: m,
		}

		for !_authenticated {
			// CPU Load High
			for util.CPU_HIGH {
				err := util.ProcessBackoff()
				if err != nil {
					return nil, err
				}
			}

			select {
			case ch <- ctx:
				go serviceAccount.Authenticate(ch, auth)
				_authenticated = true
			default:
				// Channel Full
				err := util.ProcessBackoff()
				if err != nil {
					return nil, err
				}
			}
		}

		service := <-auth
		err := service.Error
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, types.ServiceAuthenticationContextKey, service.Account)

	// Provisioner Account Authentication
	case types.ProvisionerAuthentication:
		provisionerAccount := &ProvisionerAccount{
			middleware: m,
		}
		provisioner, err := provisionerAccount.Authenticate(ctx)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, types.ProvisionerAuthenticationContextKey, provisioner)
	}
	return handler(ctx, req)
}
