package util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/pkg/types"
)

func ParseCertificateFormat(certificate *apiv1.SignedCertificate, parameter types.SignedCertificate) error {
	// Leaf Certificate Path
	if len(parameter.CertificatePath) != 0 {
		certificate := []byte(certificate.Certificate)
		if err := os.WriteFile(parameter.CertificatePath, certificate, os.ModePerm); err != nil {
			return fmt.Errorf("error writing certificate to [%s]", parameter.CertificatePath)
		}
	}

	// Intermediate Certificate Chain Path
	if len(parameter.IntermediateCertificateChainPath) != 0 {
		certificate := []byte(certificate.IntermediateCertificateChain)
		if err := os.WriteFile(parameter.IntermediateCertificateChainPath, certificate, os.ModePerm); err != nil {
			return fmt.Errorf("error writing certificate to [%s]", parameter.IntermediateCertificateChainPath)
		}
	}

	// Root Certificate Chain Path
	if len(parameter.RootCertificateChainPath) != 0 {
		certificate := []byte(certificate.CertificateChain)
		if err := os.WriteFile(parameter.RootCertificateChainPath, certificate, os.ModePerm); err != nil {
			return fmt.Errorf("error writing certificate chain to [%s]", parameter.RootCertificateChainPath)
		}
	}
	return nil
}

func GenerateCertificatePool(tc types.TrustChain) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	for _, dir := range tc.CertificateAuthorityDirectory {
		files, err := os.ReadDir(dir)
		if err != nil {
			return nil, errors.New("invalid certificate authority directory")
		}

		for _, certFile := range files {
			certificateFile := filepath.Join(dir, certFile.Name())
			data, err := os.ReadFile(filepath.Clean(certificateFile))
			if err != nil {
				return nil, errors.New("invalid certificate file")
			}
			pemBlock, _ := pem.Decode(data)
			if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
				return nil, errors.New("invalid input file")
			}
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return nil, errors.New("error parsing x.509 certificate")
			}
			certPool.AddCert(cert)
		}
	}

	for _, ca := range tc.CertificateAuthorityFiles {
		data, err := os.ReadFile(filepath.Clean(ca))
		if err != nil {
			return nil, errors.New("invalid certificate authority file")
		}
		pemBlock, _ := pem.Decode(data)
		if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
			return nil, errors.New("invalid input file")
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, errors.New("error parsing x.509 certificate")
		}
		certPool.AddCert(cert)
	}
	return certPool, nil
}
