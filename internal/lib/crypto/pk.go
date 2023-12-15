package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coinbase/baseca/internal/types"
)

func GetSubordinateCaParameters(service string) (*types.CertificateAuthority, error) {
	subordinatePath := filepath.Join(types.SubordinatePath, service+_subordinateCertificate)
	subordinate, err := readFileFromSystem(subordinatePath)
	if err != nil {
		return nil, fmt.Errorf("error reading subordinate ca from %s: %w", subordinatePath, err)
	}

	subordinatePem, _ := pem.Decode(*subordinate)
	if subordinatePem == nil {
		return nil, fmt.Errorf("error decoding subordinate PEM")
	}

	subordinateCertificate, err := x509.ParseCertificate(subordinatePem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing subordinate certificate: %w", err)
	}

	privateKeyPath := filepath.Join(types.SubordinatePath, service+_subordinatePrivateKey)
	pk, err := readFileFromSystem(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading subordinate ca key from %s: %w", privateKeyPath, err)
	}

	pkPem, _ := pem.Decode(*pk)
	if pkPem == nil {
		return nil, fmt.Errorf("error decoding private key")
	}

	serialNumberPath := filepath.Join(types.SubordinatePath, service+_subordinateSerialNumber)
	caSerialNumber, err := readFileFromSystem(serialNumberPath)
	if err != nil {
		return nil, fmt.Errorf("error reading subordinate ca serial number from %s: %w", serialNumberPath, err)
	}

	caArnPath := filepath.Join(types.SubordinatePath, service+_certificateAuthorityArn)
	caArn, err := readFileFromSystem(caArnPath)
	if err != nil {
		return nil, fmt.Errorf("error reading subordinate ca arn from %s: %w", caArnPath, err)
	}

	return &types.CertificateAuthority{
		Certificate:             subordinateCertificate,
		PrivateKey:              pkPem,
		SerialNumber:            string(*caSerialNumber),
		CertificateAuthorityArn: string(*caArn),
	}, nil
}

func readFileFromSystem(path string) (*[]byte, error) {
	if !strings.HasPrefix(path, types.SubordinatePath) {
		return nil, fmt.Errorf("unsafe file input path")
	}

	file, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return &file, err
}

func writeFileToSystem(path string, data []byte) error {
	if !strings.HasPrefix(path, types.SubordinatePath) {
		return fmt.Errorf("unsafe file input, write private key")
	}

	if err := os.WriteFile(path, data, os.ModePerm); err != nil {
		return err
	}
	return nil
}
