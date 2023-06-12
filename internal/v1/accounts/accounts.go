package accounts

import (
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/config"
)

type Service struct {
	apiv1.ServiceServer
	store       db.DatabaseEndpoints
	acmConfig   map[string]config.SubordinateCertificate
	environment config.Environment
}

func New(cfg *config.Config, endpoints db.DatabaseEndpoints) *Service {
	return &Service{
		store:       endpoints,
		acmConfig:   cfg.ACMPCA,
		environment: cfg.Environment,
	}
}
