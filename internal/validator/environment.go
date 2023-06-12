package validator

import (
	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/types"
)

const (
	BaseDirectory = "/tmp/baseca/ssl"
)

var CertificateAuthorityEnvironments map[string][]string

func SupportedEnvironments(cfg *config.Config) {
	CertificateAuthorityEnvironments = map[string][]string{
		"local":          cfg.Environment.Local,
		"sandbox":        cfg.Environment.Sandbox,
		"development":    cfg.Environment.Development,
		"staging":        cfg.Environment.Staging,
		"pre_production": cfg.Environment.PreProduction,
		"production":     cfg.Environment.Production,
		"corporate":      cfg.Environment.Corporate,
	}
}

func SetBaseDirectory(cfg *config.Config) {
	if len(cfg.SubordinateMetadata.BaseDirectory) != 0 {
		types.SubordinatePath = cfg.SubordinateMetadata.BaseDirectory
	} else {
		types.SubordinatePath = BaseDirectory
	}
}
