package validator

import (
	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/types"
)

const (
	BaseDirectory = "/tmp/baseca/ssl"
)

var CertificateAuthorityEnvironments map[types.EnvironmentKey][]string
var CertificateAuthorityEnvironmentsString map[string][]string

func SupportedEnvironments(cfg *config.Config) {
	CertificateAuthorityEnvironments = map[types.EnvironmentKey][]string{
		types.Local:         cfg.Environment.Local,
		types.Sandbox:       cfg.Environment.Sandbox,
		types.Development:   cfg.Environment.Development,
		types.Staging:       cfg.Environment.Staging,
		types.PreProduction: cfg.Environment.PreProduction,
		types.Production:    cfg.Environment.Production,
		types.Corporate:     cfg.Environment.Corporate,
	}

	CertificateAuthorityEnvironmentsString = map[string][]string{
		types.Local.String():         cfg.Environment.Local,
		types.Sandbox.String():       cfg.Environment.Sandbox,
		types.Development.String():   cfg.Environment.Development,
		types.Staging.String():       cfg.Environment.Staging,
		types.PreProduction.String(): cfg.Environment.PreProduction,
		types.Production.String():    cfg.Environment.Production,
		types.Corporate.String():     cfg.Environment.Corporate,
	}
}

func SetBaseDirectory(cfg *config.Config) {
	if len(cfg.SubordinateMetadata.BaseDirectory) != 0 {
		types.SubordinatePath = cfg.SubordinateMetadata.BaseDirectory
	} else {
		types.SubordinatePath = BaseDirectory
	}
}
