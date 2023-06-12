package apiservice

import (
	"context"
	"fmt"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/casbin/casbin/v2"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/authentication"
	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/v1/accounts"
	"github.com/coinbase/baseca/internal/v1/certificate"
	"github.com/coinbase/baseca/internal/v1/middleware"
	"github.com/coinbase/baseca/internal/v1/users"
)

const (
	// Local Memory (Authentication)
	_default_cleanup = 10 * time.Minute
)

type Server struct {
	apiv1.CertificateServer
	Store       db.DatabaseEndpoints
	Auth        authentication.Auth
	Service     *accounts.Service
	Certificate *certificate.Certificate
	User        *users.User
	Middleware  *middleware.Middleware
}

func BuildServer(store db.DatabaseEndpoints, cfg *config.Config, enforcer *casbin.Enforcer) (*Server, error) {
	signer, err := authentication.BuildSigningClient(cfg)
	if err != nil {
		return nil, err
	}

	auth, err := authentication.NewAuthSigningMetadata(signer)
	if err != nil {
		return nil, err
	}

	cache, err := bigcache.New(context.Background(), bigcache.DefaultConfig(_default_cleanup))
	if err != nil {
		return nil, fmt.Errorf("error instantiating memory cache")
	}

	service := accounts.New(cfg, store)
	user := users.New(cfg, store, auth)
	middleware := middleware.New(auth, store, enforcer, cache)
	certificate, err := certificate.New(cfg, store)
	if err != nil {
		return nil, fmt.Errorf("issue instantiating certificate client [%s]", err)
	}

	server := &Server{
		Store:       store,
		Auth:        auth,
		Service:     service,
		Certificate: certificate,
		User:        user,
		Middleware:  middleware,
	}

	return server, nil
}
