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

func BuildCertificateChain(ca_path string, certificate []byte, subordinate_ca []byte) (*bytes.Buffer, *bytes.Buffer, *bytes.Buffer, error) {
	var err error
	leaf_certificate := new(bytes.Buffer)
	intermediate_chained_certificate := new(bytes.Buffer)
	root_chained_certificate := new(bytes.Buffer)

	intermediate_ca, root_ca, err := retrieveCertificateAuthority(ca_path)
	if err != nil {
		return nil, nil, nil, err
	}

	// End Entity Certificate
	err = pem.Encode(leaf_certificate, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return nil, nil, nil, err
	}

	// Build Intermediate Certificate Chain
	err = pem.Encode(intermediate_chained_certificate, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return nil, nil, nil, err
	}

	var intermediate_chain [][]byte
	if intermediate_ca != nil {
		intermediate_chain = [][]byte{subordinate_ca, intermediate_ca}
	}

	for _, crt := range intermediate_chain {
		err = pem.Encode(intermediate_chained_certificate, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Build Root Certificate Chains Depending on Existence of Intermediate CA
	err = pem.Encode(root_chained_certificate, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return nil, nil, nil, err
	}

	var root_chain [][]byte
	if intermediate_ca != nil {
		root_chain = [][]byte{subordinate_ca, intermediate_ca, root_ca}
	} else {
		root_chain = [][]byte{subordinate_ca, root_ca}
	}

	for _, crt := range root_chain {
		err = pem.Encode(root_chained_certificate, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return leaf_certificate, intermediate_chained_certificate, root_chained_certificate, nil
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

func retrieveCertificateAuthority(service string) ([]byte, []byte, error) {
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
