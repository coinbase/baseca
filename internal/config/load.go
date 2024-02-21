package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/coinbase/baseca/internal/logger"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	configuration = "config.test.local.sandbox.yml"
)

type configProvider struct {
	v *viper.Viper
}

var _ ConfigProvider = (*configProvider)(nil)

func BuildViper(path string) (*viper.Viper, error) {
	ctxLogger := logger.ContextLogger{Logger: logger.DefaultLogger}
	ctxLogger.Info("setting up Viper to load configuration", zap.String("config-path", path))

	v := viper.New()
	v.SetConfigFile(path)
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	return v, nil
}

func LoadConfig(viper *viper.Viper) (*Config, error) {
	if viper == nil {
		return nil, errors.New("failed to load config")
	}

	c := Config{}
	if err := viper.Unmarshal(&c); err != nil {
		return nil, errors.New("failed to read configuration file")
	}
	return &c, nil
}

func NewConfigProviderFromViper(v *viper.Viper) ConfigProvider {
	return &configProvider{v: v}
}

func (cp *configProvider) Get(path string, cfg any) error {
	if !cp.Exists(path) {
		return fmt.Errorf("path %s is not found in configuration", path)
	}

	if err := cp.v.UnmarshalKey(path, cfg, func(setting *mapstructure.DecoderConfig) {
		setting.ErrorUnused = true
		setting.ZeroFields = true
	}); err != nil {
		return err
	}

	if u, ok := cfg.(interface{ Validate() error }); ok {
		if err := u.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (cp *configProvider) Exists(path string) bool {
	return cp.v.Get(path) != nil
}

func GetTestConfigurationPath() (*Config, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("Error: Unable to get current file path")
	}

	baseDir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(baseDir, "go.mod")); err == nil {
			break
		}

		parentDir := filepath.Dir(baseDir)
		if parentDir == baseDir {
			log.Fatal("Error: Unable to find base directory")
			break
		}

		baseDir = parentDir
	}

	path := fmt.Sprintf("%s/config/%s", baseDir, configuration)
	config, err := provideConfig(path)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func provideConfig(path string) (*Config, error) {
	ctxLogger := logger.ContextLogger{Logger: logger.DefaultLogger}

	v, err := BuildViper(path)
	if err != nil {
		ctxLogger.Error(err.Error())
	}

	config, err := LoadConfig(v)
	if err != nil {
		return nil, err
	}

	return config, err
}
