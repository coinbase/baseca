package middleware

import (
	"github.com/allegro/bigcache/v3"
	"github.com/casbin/casbin/v2"
	db "github.com/coinbase/baseca/db/sqlc"
	"github.com/coinbase/baseca/internal/authentication"
)

const (
	// User Authorization
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"

	// Service Authorization
	clientIdAuthorizationHeaderKey    = "x-baseca-client-id"    // #nosec G101 False Positive
	clientTokenAuthorizationHeaderKey = "x-baseca-client-token" // #nosec G101 False Positive
	clientIdentityDocumentHeaderKey   = "x-baseca-instance-metadata"

	// Enrollment Authorization
	enrollmentIdAuthorizationHeaderKey = "x-baseca-enrollment-id"
	enrollmentAuthorizationHeaderToken = "x-baseca-enrollment-token" // #nosec G101 False Positive
)

type Middleware struct {
	auth     authentication.Auth
	store    db.DatabaseEndpoints
	enforcer *casbin.Enforcer
	cache    *bigcache.BigCache
}

func New(auth authentication.Auth, endpoints db.DatabaseEndpoints, enforcer *casbin.Enforcer, cache *bigcache.BigCache) *Middleware {
	return &Middleware{
		auth:     auth,
		store:    endpoints,
		enforcer: enforcer,
		cache:    cache,
	}
}
