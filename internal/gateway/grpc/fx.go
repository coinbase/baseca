package grpc

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"

	"github.com/casbin/casbin/v2"
	apiservice "github.com/coinbase/baseca/cmd/server/baseca"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/client/secretsmanager"
	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/v1/certificate"
	"github.com/coinbase/baseca/internal/v1/health"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

const (
	authorization_path = "internal/authorization/casbin"
)

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
		log.Fatalf("error getting database credentials", err)
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

	authorization_model := fmt.Sprintf("%s/model.conf", authorization_path)
	authorization_policy := fmt.Sprintf("%s/policy.csv", authorization_path)
	enforcer, _ := casbin.NewEnforcer(authorization_model, authorization_policy)

	writer_endpoint := db.BuildDatastore(database_endpoint)
	reader_endpoint := db.BuildDatastore(database_reader_endpoint)
	db := db.DatabaseEndpoints{Writer: writer_endpoint, Reader: reader_endpoint}

	// RPC Server
	server, err := apiservice.BuildServer(db, cfg, enforcer)
	if err != nil {
		log.Fatal("cannot Start grpc server", err)
	}

	extractor := func(resp interface{}, err error, code codes.Code) string {
		if err != nil {
			if customErr, ok := err.(*logger.Error); ok {
				return customErr.InternalError.Error()
			}
			return err.Error()
		}
		return "success"
	}

	term := make(chan error)
	var grpcServer *grpc.Server

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {

			// RPC Middleware Logger
			logInterceptor := logger.RpcLogger(extractor)
			interceptors := grpc_middleware.ChainUnaryServer(logInterceptor, server.Middleware.ServerAuthenticationInterceptor)
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

func GetPgConn(conf config.DatabaseConfig, endpoint, credentials string) (*sql.DB, error) {
	dataSource := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s", endpoint, conf.Port, conf.User, credentials, conf.Table)

	if conf.SSLMode == "disable" {
		dataSource = fmt.Sprintf("%s sslmode=disable", dataSource)
	} else {
		dataSource = fmt.Sprintf("%s sslmode=verify-full sslrootcert=internal/attestor/aws_iid/certificate/rds.global.bundle.pem", dataSource)
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
