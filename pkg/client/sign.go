package baseca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
)

func (c *client) GenerateSignature(csr CertificateRequest, element []byte) (*[]byte, []*x509.Certificate, error) {
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

	err = parseCertificateFormat(signedCertificate, SignedCertificate{
		CertificatePath:                  csr.Output.Certificate,
		IntermediateCertificateChainPath: csr.Output.IntermediateCertificateChain,
		RootCertificateChainPath:         csr.Output.RootCertificateChain})

	if err != nil {
		return nil, nil, err
	}

	hashedOutput := sha256.Sum256(element)
	pk, err := x509.ParsePKCS1PrivateKey(signingRequest.PrivateKey.Bytes)
	if err != nil {
		return nil, nil, errors.New("error parsing pkcs1 private key")
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, hashedOutput[:])
	if err != nil {
		return nil, nil, fmt.Errorf("error calculating signature of hash using pkcs1: %s", err)
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

func (c *client) ValidateSignature(certificates []*x509.Certificate, signature []byte, element []byte, cn string, ca string) error {
	err := certificates[0].CheckSignature(x509.SHA256WithRSA, element, signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %s", err)
	}

	// Validate Entire Certificate Chain Valid
	for i := range certificates[:len(certificates)-1] {
		err = certificates[i].CheckSignatureFrom(certificates[i+1])
		if err != nil {
			return fmt.Errorf("certificate chain invalid: %s", err)
		}
	}

	if certificates[0].Subject.CommonName != cn {
		return fmt.Errorf("invalid common name (cn) from code signing certificate")
	}

	validSubjectAlternativeName := false
	if len(certificates[0].DNSNames) > 0 {
		for _, san := range certificates[0].DNSNames {
			if san == cn {
				validSubjectAlternativeName = true
			}
		}
	}

	if !validSubjectAlternativeName {
		return fmt.Errorf("invalid subject alternative name (san) from code signing certificate")
	}

	rootCertificatePool, err := c.generateCertificatePool(ca)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots:     rootCertificatePool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	_, err = certificates[1].Verify(opts)
	if err != nil {
		return fmt.Errorf("error validating code signing certificate validity: %s", err)
	}
	return nil
}

func (c *client) generateCertificatePool(ca string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	files, err := os.ReadDir(ca)
	if err != nil {
		return nil, errors.New("invalid certificate authority directory")
	}

	for _, certFile := range files { // #nosec G304 User Only Has Predefined Environment Parameters
		data, err := os.ReadFile(filepath.Join(ca, certFile.Name()))
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
	return certPool, nil
}
