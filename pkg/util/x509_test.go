package util

import (
	"os"
	"path/filepath"
	"testing"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/pkg/types"
)

func TestParseCertificateFormat(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "certificate")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certificatePath := filepath.Join(tempDir, "certificate.pem")
	intermediateCertificateChainPath := filepath.Join(tempDir, "intermediate.pem")
	rootCertificateChainPath := filepath.Join(tempDir, "root.pem")

	certificate := &apiv1.SignedCertificate{
		Certificate:                  "-----BEGIN CERTIFICATE-----",
		IntermediateCertificateChain: "-----BEGIN CERTIFICATE-----",
		CertificateChain:             "-----BEGIN CERTIFICATE-----",
	}
	parameters := types.SignedCertificate{
		CertificatePath:                  certificatePath,
		IntermediateCertificateChainPath: intermediateCertificateChainPath,
		RootCertificateChainPath:         rootCertificateChainPath,
	}

	err = ParseCertificateFormat(certificate, parameters)
	if err != nil {
		t.Fatalf("failed to parse certificate format: %v", err)
	}

	for _, path := range []string{certificatePath, intermediateCertificateChainPath, rootCertificateChainPath} {
		_, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file %s: %v", path, err)
		}
	}
}
