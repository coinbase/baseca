package middleware

import (
	"github.com/allegro/bigcache/v3"
	"github.com/casbin/casbin/v2"
	db "github.com/coinbase/baseca/db/sqlc"
	lib "github.com/coinbase/baseca/internal/lib/authentication"
)

const (
	// User Authorization
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"

	// Service Authorization
	clientIdAuthorizationHeaderKey    = "x-baseca-client-id"    // #nosec G101 False Positive
	clientTokenAuthorizationHeaderKey = "x-baseca-client-token" // #nosec G101 False Positive
	clientIdentityDocumentHeaderKey   = "x-baseca-instance-metadata"
)

type Middleware struct {
	auth     lib.Auth
	store    db.DatabaseEndpoints
	enforcer *casbin.Enforcer
	cache    *bigcache.BigCache
}

func New(auth lib.Auth, endpoints db.DatabaseEndpoints, enforcer *casbin.Enforcer, cache *bigcache.BigCache) *Middleware {
	return &Middleware{
		auth:     auth,
		store:    endpoints,
		enforcer: enforcer,
		cache:    cache,
	}
}
