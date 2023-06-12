package environment

import (
	"os"
)

const (
	_Configuration        = "CONFIGURATION"
	_Environment          = "ENVIRONMENT"
	_AWSProvider          = "aws"
	_LocalProvider        = "sandbox"
	_LocalStage           = "local"
	_PrimaryConfiguration = "primary"
)

type Environment struct {
	Provider      string
	Stage         string
	Configuration string
}

func ProvideEnvironment() Environment {
	result := Environment{
		Provider:      getProvider(),
		Stage:         getStage(),
		Configuration: getConfiguration(),
	}
	return result
}

func getProvider() string {
	if os.Getenv(_Environment) != "" {
		return _AWSProvider
	}
	return _LocalProvider
}

func getStage() string {
	configStage := os.Getenv(_Configuration)
	if len(configStage) != 0 {
		return configStage
	}
	return _LocalStage
}

func getConfiguration() string {
	switch os.Getenv(_Configuration) {
	default:
		return _PrimaryConfiguration
	}
}
