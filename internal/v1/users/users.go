package users

import (
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/config"
	lib "github.com/coinbase/baseca/internal/lib/authentication"
)

type User struct {
	apiv1.AccountServer
	store    db.DatabaseEndpoints
	auth     lib.Auth
	validity int
}

func New(cfg *config.Config, endpoints db.DatabaseEndpoints, auth lib.Auth) *User {
	return &User{
		store:    endpoints,
		auth:     auth,
		validity: cfg.KMS.AuthValidity,
	}
}
