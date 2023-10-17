package main

import (
	"context"
	"log"
	"time"

	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/gateway"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	_ "github.com/lib/pq"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

func main() {

	app := fx.New(
		fx.Options(
			config.Module,
			gateway.Module,
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
