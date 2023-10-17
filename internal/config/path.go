package config

import (
	"fmt"

	"github.com/bazelbuild/rules_go/go/tools/bazel"
)

const (
	_template = "config/config.%s.yml"
)

type ConfigFilePathResolver interface {
	Resolve() (string, error)
}

type Resolver struct {
	Environment Environment
	Template    string
}

func ProvideConfigPathResolver(e Environment) ConfigFilePathResolver {
	return &Resolver{Environment: e, Template: _template}
}

var _ ConfigFilePathResolver = (*Resolver)(nil)

func (r Resolver) Resolve() (string, error) {
	configurationFileName := configurationFileName(r.Environment)
	location := fmt.Sprintf(r.Template, configurationFileName)

	path, err := bazel.Runfile(location)
	if err != nil {
		return "", fmt.Errorf(location)
	}
	return path, nil
}

func configurationFileName(e Environment) string {
	return fmt.Sprintf("%s.%s.%s", e.Configuration, e.Stage, e.Provider)
}
