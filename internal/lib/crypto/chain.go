package crypto

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coinbase/baseca/internal/types"
)

const (
	_subordinatePrivateKey   = "/ca-subordinate.key"
	_subordinateCertificate  = "/ca-subordinate.crt"
	_subordinateSerialNumber = "/serial.txt"
	_intermediateCertificate = "/ca-intermediate.crt"
	_certificateAuthorityArn = "/acm-pca.txt"
	_rootCertificate         = "/ca-root.crt"
)

func BuildCertificateChain(intermediateCa string, certificate []byte, caCertificate []byte) (*bytes.Buffer, *bytes.Buffer, error) {
	var err error
	leaf_certificate := new(bytes.Buffer)
	chained_certificate := new(bytes.Buffer)

	intermediate_ca, root_ca, err := getCertificateChain(intermediateCa)
	if err != nil {
		return nil, nil, err
	}

	// Leaf Certificate
	err = pem.Encode(leaf_certificate, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return nil, nil, err
	}

	// Certificate Chain
	err = pem.Encode(chained_certificate, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return nil, nil, err
	}

	// Build the chain based on the existence of intermediate_ca
	var chain [][]byte
	if intermediate_ca != nil {
		chain = [][]byte{caCertificate, intermediate_ca, root_ca}
	} else {
		chain = [][]byte{caCertificate, root_ca}
	}

	for _, certificate := range chain {
		err = pem.Encode(chained_certificate, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
		if err != nil {
			return nil, nil, err
		}
	}

	return leaf_certificate, chained_certificate, nil
}

func GetSubordinateCaPath(service string) (*string, *string, error) {
	directoryPath := filepath.Join(types.SubordinatePath, service)

	caPath := filepath.Join(directoryPath, _subordinateCertificate)
	if !strings.HasPrefix(caPath, types.SubordinatePath) {
		return nil, nil, fmt.Errorf("unsafe file input, read ca subordinate certificate")
	}

	keyPath := filepath.Join(directoryPath, _subordinatePrivateKey)
	if !strings.HasPrefix(caPath, types.SubordinatePath) {
		return nil, nil, fmt.Errorf("unsafe file input, read ca subordinate private key")
	}

	return &caPath, &keyPath, nil
}

func getCertificateChain(service string) ([]byte, []byte, error) {
	intermediatePath := filepath.Join(types.SubordinatePath, service+_intermediateCertificate)
	rootPath := filepath.Join(types.SubordinatePath, service+_rootCertificate)

	if !strings.HasPrefix(intermediatePath, types.SubordinatePath) || !strings.HasPrefix(rootPath, types.SubordinatePath) {
		return nil, nil, fmt.Errorf("unsafe file input")
	}

	var x509_intermediate_ca *x509.Certificate
	if _, err := os.Stat(intermediatePath); !os.IsNotExist(err) {
		intermediate_ca, err := os.ReadFile(filepath.Clean(intermediatePath))
		if err != nil {
			return nil, nil, err
		}
		x509_intermediate_ca, err = parseCertificate(intermediate_ca)
		if err != nil {
			return nil, nil, err
		}
	}

	root_ca, err := os.ReadFile(filepath.Clean(rootPath))
	if err != nil {
		return nil, nil, err
	}

	x509_root_ca, err := parseCertificate(root_ca)
	if err != nil {
		return nil, nil, err
	}

	var intermediateRaw []byte
	if x509_intermediate_ca != nil {
		intermediateRaw = x509_intermediate_ca.Raw
	}
	return intermediateRaw, x509_root_ca.Raw, nil
}

func parseCertificate(ca []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(ca)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
