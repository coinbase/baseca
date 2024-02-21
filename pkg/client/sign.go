package baseca

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

func (c *Client) GenerateSignature(s types.Signature) (*[]byte, []*x509.Certificate, error) {
	var certificatePem []*pem.Block
	var certificateChain []*x509.Certificate
	var artifactHash []byte

	signingRequest, err := GenerateCSR(s.CertificateRequest)
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
		CertificatePath:                  s.CertificateRequest.Output.Certificate,
		IntermediateCertificateChainPath: s.CertificateRequest.Output.IntermediateCertificateChain,
		RootCertificateChainPath:         s.CertificateRequest.Output.RootCertificateChain,
	})
	if err != nil {
		return nil, nil, err
	}

	signer, err := parsePrivateKey(signingRequest.EncodedPKCS8, s.SigningAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	// Sign Artifact
	switch {
	case s.Data.Path != types.Path{}:
		artifactHash, err = streamSignature(s)
		if err != nil {
			return nil, nil, fmt.Errorf("[data.path] %s", err)
		}
	case s.Data.Reader != types.Reader{}:
		artifactHash, err = readerSignature(s)
		if err != nil {
			return nil, nil, fmt.Errorf("[data.reader] %s", err)
		}
	case s.Data.Raw != nil:
		artifactHash, err = signer.Sign(*s.Data.Raw)
		if err != nil {
			return nil, nil, fmt.Errorf("[data.raw] %s", err)
		}
	default:
		return nil, nil, errors.New("data not present within manifest")
	}

	signature, err := signer.Sign(artifactHash)
	if err != nil {
		return nil, nil, fmt.Errorf("error signing data: %w", err)
	}

	fullChain, err := os.ReadFile(filepath.Clean(s.CertificateRequest.Output.RootCertificateChain))
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

// Stream Large Files and Sign the Hash by Passing in Filepath
func streamSignature(s types.Signature) ([]byte, error) {
	algorithm, exists := types.SignatureAlgorithm[s.SigningAlgorithm]
	if !exists {
		return nil, fmt.Errorf("invalid signing algorithm: %s", s.SigningAlgorithm)
	}
	hashedAlgorithm, _ := algorithm()

	file, err := os.Open(s.Data.Path.File)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %s", err)
	}
	defer file.Close()

	if s.Data.Reader.Buffer > 0 {
		_buffer = s.Data.Reader.Buffer
	}

	buffer := make([]byte, _buffer)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("error reading file: %s", err)
		}
		if n == 0 {
			break
		}
		hashedAlgorithm.Write(buffer[:n])
	}

	return hashedAlgorithm.Sum(nil), nil
}

func readerSignature(s types.Signature) ([]byte, error) {
	algorithm, exist := types.SignatureAlgorithm[s.SigningAlgorithm]
	if !exist {
		return nil, fmt.Errorf("invalid signing algorithm: %s", s.SigningAlgorithm)
	}
	hashedAlgorithm, _ := algorithm()

	if s.Data.Reader.Buffer > 0 {
		_buffer = s.Data.Reader.Buffer
	}

	buffer := make([]byte, _buffer)
	for {
		n, err := s.Data.Reader.Interface.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("error reading file: %s", err)
		}
		if n == 0 {
			break
		}
		hashedAlgorithm.Write(buffer[:n])
	}

	return hashedAlgorithm.Sum(nil), nil
}
