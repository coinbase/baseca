package validator

import (
	"testing"

	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/types"
)

func TestSupportedEnvironments(t *testing.T) {
	cfg := &config.Config{
		Environment: config.Stage{
			Local: []string{"localhost"},
		},
	}

	SupportedEnvironments(cfg)

	if len(CertificateAuthorityEnvironments["local"]) == 0 {
		t.Errorf("Expected non-empty local environments, got none")
	}
}

func TestSetBaseDirectory(t *testing.T) {
	// When BaseDirectory is provided
	cfg := &config.Config{
		SubordinateMetadata: config.SubordinateCertificateAuthority{
			BaseDirectory: "/some/dir",
		},
	}

	SetBaseDirectory(cfg)

	if types.SubordinatePath != "/some/dir" {
		t.Errorf("Expected SubordinatePath to be set to '/some/dir', got: %s", types.SubordinatePath)
	}

	cfg.SubordinateMetadata.BaseDirectory = ""

	SetBaseDirectory(cfg)

	if types.SubordinatePath != BaseDirectory {
		t.Errorf("Expected SubordinatePath to be set to BaseDirectory, got: %s", types.SubordinatePath)
	}
}
