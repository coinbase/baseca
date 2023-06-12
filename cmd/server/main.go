package main

import (
	"context"
	"log"
	"time"

	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/environment"
	"github.com/coinbase/baseca/internal/gateway/grpc"
	"github.com/coinbase/baseca/internal/validator"
	_ "github.com/lib/pq"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

func main() {

	app := fx.New(
		fx.Options(
			config.Module,
			environment.Module,
			grpc.Module,
			validator.Module,
		),
		fx.WithLogger(
			func() fxevent.Logger {
				return fxevent.NopLogger
			},
		),
	)

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.Start(startCtx); err != nil {
		log.Fatal(err)
	}

	<-app.Done()

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := app.Stop(stopCtx); err != nil {
		log.Fatal(err)
	}
}
