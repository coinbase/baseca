package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/coinbase/baseca/internal/types"
)

func WriteKeyToFile(service string, privateKey types.AsymmetricKey) error {
	var pemBlock *pem.Block
	directoryPath := filepath.Join(types.SubordinatePath, service)
	filePath := filepath.Join(directoryPath, _subordinatePrivateKey)

	if !strings.HasPrefix(filePath, types.SubordinatePath) {
		return fmt.Errorf("unsafe file input, write private key")
	}

	switch k := privateKey.KeyPair().(type) {
	case *RSA:
		pkBytes := x509.MarshalPKCS1PrivateKey(k.PrivateKey)
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pkBytes,
		}
	case *ECDSA:
		pkBytes, err := x509.MarshalECPrivateKey(k.PrivateKey)
		if err != nil {
			return err
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: pkBytes,
		}
	default:
		return fmt.Errorf("private key format not supported")
	}

	if err := os.WriteFile(filePath, pem.EncodeToMemory(pemBlock), os.ModePerm); err != nil {
		return err
	}

	return nil
}

func WriteSubordinateCaParameters(service string, caCertificate *x509.Certificate, ca types.CertificateParameters, pca *acmpca.GetCertificateAuthorityCertificateOutput) error {
	var err error

	directoryPath := filepath.Join(types.SubordinatePath, service)

	// Subordinate CA
	filePath := filepath.Join(directoryPath, _subordinateCertificate)
	pemBlock := encodeCertificateFromx509(caCertificate)
	if err := os.WriteFile(filePath, *pemBlock, os.ModePerm); err != nil {
		return err
	}

	if !ca.RootCa {
		filePath = filepath.Join(directoryPath, _intermediateCertificate)
		pemBlock, err = encodeCertificateFromString(pca.Certificate)
		if err != nil {
			return fmt.Errorf("error encoding intermediate ca")
		}
		if err := os.WriteFile(filePath, *pemBlock, os.ModePerm); err != nil {
			return fmt.Errorf("error writing intermediate ca to filesystem")
		}

		filePath = filepath.Join(directoryPath, _rootCertificate)
		pemBlock, err = encodeCertificateFromString(pca.CertificateChain)
		if err != nil {
			return fmt.Errorf("error encoding root ca")
		}
		if err := os.WriteFile(filePath, *pemBlock, os.ModePerm); err != nil {
			return fmt.Errorf("error writing root ca to filesystem")
		}
	} else {
		filePath = filepath.Join(directoryPath, _rootCertificate)
		pemBlock, err = encodeCertificateFromString(pca.Certificate)
		if err != nil {
			return fmt.Errorf("error encoding root ca")
		}
		if err := os.WriteFile(filePath, *pemBlock, os.ModePerm); err != nil {
			return fmt.Errorf("error writing root ca to filesystem")
		}
	}

	// Certificate Authority Serial Number
	ca_serial_number := fmt.Sprintf("%x", caCertificate.SerialNumber)
	filePath = filepath.Join(directoryPath, _subordinateSerialNumber)
	err = writeFileToSystem(filePath, []byte(ca_serial_number))
	if err != nil {
		return fmt.Errorf("error writing serial number to filesystem")
	}

	// Intermediate ACM Private CA ARN
	filePath = filepath.Join(directoryPath, _certificateAuthorityArn)
	err = writeFileToSystem(filePath, []byte(ca.CaArn))
	if err != nil {
		return fmt.Errorf("error writing ca arn to filesystem")
	}
	return nil
}

func encodeCertificateFromString(certificate *string) (*[]byte, error) {
	c := []byte(*certificate)
	block, _ := pem.Decode(c)
	x509Certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid x509 certificate format")
	}
	pemBlock := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: x509Certificate.Raw,
		},
	)
	return &pemBlock, nil
}

func encodeCertificateFromx509(certificate *x509.Certificate) *[]byte {
	pemBlock := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		},
	)
	return &pemBlock
}
