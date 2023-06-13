package config

import (
	"log"

	"github.com/coinbase/baseca/internal/environment"
	"github.com/coinbase/baseca/internal/logger"
	"go.uber.org/fx"
)

var Module = fx.Options(
	fx.Provide(
		ProvideConfigPathResolver,
		ProvideConfig,
	),
)

var Configuration *Config

type Parameter struct {
	fx.In

	Environment  environment.Environment
	PathResolver ConfigFilePathResolver
}

type Result struct {
	fx.Out

	RawConfig      *Config
	ConfigProvider ConfigProvider
}

type ConfigProvider interface {
	Get(path string, cfg interface{}) error
	Exists(path string) bool
}

func ProvideConfig(p Parameter) (Result, error) {
	var result Result
	ctxLogger := logger.ContextLogger{Logger: logger.DefaultLogger}

	_, resolver := p.Environment, p.PathResolver
	path, err := resolver.Resolve()
	if err != nil {
		log.Fatalf("configuration file does not exist [%s]", err.Error())
	}
	ctxLogger.Info("Load Config From File, Config Path: " + path)
	v, err := BuildViper(path)
	if err != nil {
		ctxLogger.Error(err.Error())
	}

	config, err := LoadConfig(v)
	if err != nil {
		return result, err
	}

	Configuration = config // Set Globally

	result.RawConfig = config
	result.ConfigProvider = NewConfigProviderFromViper(v)

	return result, nil
}
