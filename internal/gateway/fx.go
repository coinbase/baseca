package gateway

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/casbin/casbin/v2"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/client/secretsmanager"
	"github.com/coinbase/baseca/internal/config"
	lib "github.com/coinbase/baseca/internal/lib/authentication"
	"github.com/coinbase/baseca/internal/lib/util"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/v1/accounts"
	"github.com/coinbase/baseca/internal/v1/certificate"
	"github.com/coinbase/baseca/internal/v1/health"
	"github.com/coinbase/baseca/internal/v1/middleware"
	"github.com/coinbase/baseca/internal/v1/users"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

const (
	_authorization_path = "config/permissions"
	_default_cleanup    = 10 * time.Minute
)

type Server struct {
	apiv1.CertificateServer
	Store       db.DatabaseEndpoints
	Auth        lib.Auth
	Service     *accounts.Service
	Certificate *certificate.Certificate
	User        *users.User
	Middleware  *middleware.Middleware
}

var Module = fx.Options(
	fx.Invoke(StartRPC),
)

func StartRPC(lc fx.Lifecycle, cfg *config.Config) error {
	client, err := secretsmanager.NewSecretsManagerClient(cfg)
	if err != nil {
		log.Fatalf("error instantiating secrets manager client")
	}

	credentials, err := client.GetSecretValue(cfg.SecretsManager.SecretId, secretsmanager.DATABASE_CREDENTIALS)
	if err != nil {
		log.Fatalf("error getting database credentials: %s", err)
	}

	caError := certificate.ValidateSubordinateParameters(cfg.SubordinateMetadata)
	if caError != nil {
		log.Fatalf("error in subordinate ca configuration: %s", caError)
	}

	database_endpoint, err := GetPgConn(cfg.Database, cfg.Database.Endpoint, *credentials)
	if err != nil {
		log.Fatalf("error building database writer endpoint: %s", err.Error())
	}
	database_reader_endpoint, err := GetPgConn(cfg.Database, cfg.Database.ReaderEndpoint, *credentials)
	if err != nil {
		log.Fatalf("error building database reader endpoint: %s", err.Error())
	}

	if err != nil {
		log.Fatalf("cannot connect to the database: %s", err)
	}

	authorization_model := fmt.Sprintf("%s/model.conf", _authorization_path)
	authorization_policy := fmt.Sprintf("%s/policy.csv", _authorization_path)
	enforcer, _ := casbin.NewEnforcer(authorization_model, authorization_policy)

	writer_endpoint := db.BuildDatastore(database_endpoint)
	reader_endpoint := db.BuildDatastore(database_reader_endpoint)
	db := db.DatabaseEndpoints{Writer: writer_endpoint, Reader: reader_endpoint}

	// RPC Server
	server, err := BuildServer(db, cfg, enforcer)
	if err != nil {
		log.Fatal("cannot Start grpc server", err)
	}

	extractor := func(resp any, err error, code codes.Code) string {
		if err != nil {
			if customErr, ok := err.(*logger.Error); ok && customErr.InternalError != nil {
				return customErr.InternalError.Error()
			}
			return err.Error()
		}
		return "success"
	}

	term := make(chan error)
	var grpcServer *grpc.Server

	// Monitor CPU Load
	go util.UpdateCPULoad()

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {

			// RPC Middleware Logger
			logInterceptor := logger.RpcLogger(extractor)
			interceptors := grpc_middleware.ChainUnaryServer(server.Middleware.SetAuthenticationContext, logInterceptor, server.Middleware.ServerAuthenticationInterceptor)
			grpcServer = grpc.NewServer(grpc.UnaryInterceptor(interceptors))

			// Service Registration
			apiv1.RegisterAccountServer(grpcServer, server.User)
			apiv1.RegisterServiceServer(grpcServer, server.Service)
			apiv1.RegisterCertificateServer(grpcServer, server.Certificate)

			hs := health.NewHealthServer()
			healthpb.RegisterHealthServer(grpcServer, hs)
			reflection.Register(grpcServer)

			listener, err := net.Listen("tcp", config.Configuration.GRPCServerAddress)
			if err != nil {
				log.Fatal("cannot create rpc listener")
			}

			go func() {
				term <- grpcServer.Serve(listener)
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			if grpcServer == nil {
				return nil
			}

			grpcServer.Stop()
			var err error
			select {
			case err = <-term:
			case <-ctx.Done():
				err = fmt.Errorf("context deadline: %w", err)
			}

			logger.DefaultLogger.Info("server exited:", zap.Error(err))
			return nil
		},
	})

	return nil
}

func BuildServer(store db.DatabaseEndpoints, cfg *config.Config, enforcer *casbin.Enforcer) (*Server, error) {
	signer, err := lib.BuildSigningClient(cfg)
	if err != nil {
		return nil, err
	}

	auth, err := lib.NewAuthSigningMetadata(signer)
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

func GetPgConn(conf config.DatabaseConfig, endpoint, credentials string) (*sql.DB, error) {
	dataSource := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s", endpoint, conf.Port, conf.User, credentials, conf.Table)

	if conf.SSLMode == "disable" {
		dataSource = fmt.Sprintf("%s sslmode=disable", dataSource)
	} else {
		dataSource = fmt.Sprintf("%s sslmode=verify-full sslrootcert=config/aws/rds.global.bundle.pem", dataSource)
	}

	// Open Database Connection
	sqlClient, err := sql.Open("postgres", dataSource)
	if err != nil {
		return nil, fmt.Errorf("error: The data source arguments are not valid: %v", err)
	}

	// Validate Connection
	err = sqlClient.Ping()
	if err != nil {
		return nil, fmt.Errorf("error: Could not establish a connection with the database: %v", err)
	}

	return sqlClient, nil
}
