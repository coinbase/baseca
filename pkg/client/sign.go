package baseca

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/pkg/crypto"
	"github.com/coinbase/baseca/pkg/types"
)

var _buffer = 1024

type Signer interface {
	Sign(data []byte) ([]byte, error)
}

func (c *Client) GenerateSignature(csr CertificateRequest, data *[]byte) (*[]byte, []*x509.Certificate, error) {
	var certificatePem []*pem.Block
	var certificateChain []*x509.Certificate

	signingRequest, err := GenerateCSR(csr)
	if err != nil {
		return nil, nil, err
	}

	req := apiv1.CertificateSigningRequest{
		CertificateSigningRequest: signingRequest.CSR.String(),
	}

	signedCertificate, err := c.Certificate.SignCSR(context.Background(), &req)
	if err != nil {
		return nil, nil, err
	}

	err = ParseCertificateFormat(signedCertificate, types.SignedCertificate{
		CertificatePath:                  csr.Output.Certificate,
		IntermediateCertificateChainPath: csr.Output.IntermediateCertificateChain,
		RootCertificateChainPath:         csr.Output.RootCertificateChain,
	})
	if err != nil {
		return nil, nil, err
	}

	signer, err := parsePrivateKey(signingRequest.EncodedPKCS8, csr.SigningAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	signature, err := signer.Sign(*data)
	if err != nil {
		return nil, nil, fmt.Errorf("error signing data: %w", err)
	}

	fullChain, err := os.ReadFile(filepath.Clean(csr.Output.RootCertificateChain))
	if err != nil {
		return nil, nil, fmt.Errorf("error retrieving full chain certificate: %s", err)
	}

	// Build *pem.Block for Each Certificate in Chain
	for {
		block, remainder := pem.Decode(fullChain)
		if block == nil {
			break
		}
		certificatePem = append(certificatePem, block)
		fullChain = remainder
	}

	// Build *x509.Certificate for Each Certificate in Chain
	for _, block := range certificatePem {
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing code signing certificate: %s", err)
		}
		certificateChain = append(certificateChain, certificate)
	}

	return &signature, certificateChain, nil
}

func parsePrivateKey(pk []byte, signatureAlgorithm x509.SignatureAlgorithm) (Signer, error) {
	block, _ := pem.Decode(pk)
	if block == nil {
		return nil, errors.New("error parsing pem block from private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing pkcs8 private key: %s", err)
	}

	// Validate Signing Algorithm is Supported
	algorithm, exist := types.SignatureAlgorithm[signatureAlgorithm]
	if !exist {
		return nil, fmt.Errorf("invalid signing algorithm: %s", signatureAlgorithm)
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &crypto.RSASigner{
			PrivateKey:         key,
			SignatureAlgorithm: signatureAlgorithm,
			Hash:               algorithm}, nil
	case *ecdsa.PrivateKey:
		return &crypto.ECDSASigner{
			PrivateKey:         key,
			SignatureAlgorithm: signatureAlgorithm,
			Hash:               algorithm}, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}
