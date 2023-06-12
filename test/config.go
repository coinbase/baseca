package test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/logger"
)

const (
	configuration = "config.test.local.sandbox.yml"
)

func GetTestConfigurationPath() (*config.Config, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Println("Error: Unable to get current file path")
	}

	baseDir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(baseDir, "go.mod")); err == nil {
			break
		}

		parentDir := filepath.Dir(baseDir)
		if parentDir == baseDir {
			fmt.Println("Error: Unable to find base directory")
			break
		}

		baseDir = parentDir
	}

	path := fmt.Sprintf("%s/test/config/%s", baseDir, configuration)
	config, err := provideConfig(path)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func provideConfig(path string) (*config.Config, error) {
	ctxLogger := logger.ContextLogger{Logger: logger.DefaultLogger}

	v, err := config.BuildViper(path)
	if err != nil {
		ctxLogger.Error(err.Error())
	}

	config, err := config.LoadConfig(v)
	if err != nil {
		return nil, err
	}

	return config, err
}

//
