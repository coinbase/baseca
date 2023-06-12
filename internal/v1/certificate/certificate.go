package certificate

import (
	"fmt"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	acm_pca "github.com/coinbase/baseca/internal/client/acmpca"
	"github.com/coinbase/baseca/internal/client/firehose"
	"github.com/coinbase/baseca/internal/client/redis"
	"github.com/coinbase/baseca/internal/config"
)

type Certificate struct {
	apiv1.CertificateServer
	store       db.DatabaseEndpoints
	acmConfig   map[string]config.SubordinateCertificate
	ca          config.SubordinateCertificateAuthority
	ocsp        []string
	environment config.Environment
	redis       *redis.RedisClient
	firehose    *firehose.FirehoseClient
	pca         *acm_pca.PrivateCaClient
}

func New(cfg *config.Config, endpoints db.DatabaseEndpoints) (*Certificate, error) {
	redisClient, err := redis.NewRedisClient(cfg)
	if err != nil {
		return nil, err
	}
	firehoseClient, err := firehose.NewFirehoseClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("error instantiating firehose client [%s]", err)
	}

	return &Certificate{
		store:       endpoints,
		acmConfig:   cfg.ACMPCA,
		ca:          cfg.SubordinateMetadata,
		ocsp:        cfg.OCSPServer,
		environment: cfg.Environment,
		redis:       redisClient,
		firehose:    firehoseClient,
	}, nil
}
