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
	"github.com/coinbase/baseca/pkg/types"
	"github.com/coinbase/baseca/pkg/util"
)

func (c *Client) GenerateSignature(csr CertificateRequest, element []byte) (*[]byte, []*x509.Certificate, error) {
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

	err = util.ParseCertificateFormat(signedCertificate, types.SignedCertificate{
		CertificatePath:                  csr.Output.Certificate,
		IntermediateCertificateChainPath: csr.Output.IntermediateCertificateChain,
		RootCertificateChainPath:         csr.Output.RootCertificateChain,
	})

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

func (c *Client) ValidateSignature(tc types.TrustChain, manifest types.Manifest) error {
	err := manifest.CertificateChain[0].CheckSignature(manifest.SigningAlgorithm, manifest.Data, manifest.Signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %s", err)
	}

	// Validate Entire Certificate Chain Does Not Break
	for i := range manifest.CertificateChain[:len(manifest.CertificateChain)-1] {
		err = manifest.CertificateChain[i].CheckSignatureFrom(manifest.CertificateChain[i+1])
		if err != nil {
			return fmt.Errorf("certificate chain invalid: %s", err)
		}
	}

	if manifest.CertificateChain[0].Subject.CommonName != tc.CommonName {
		return fmt.Errorf("invalid common name (cn) from code signing certificate")
	}

	validSubjectAlternativeName := false
	if len(manifest.CertificateChain[0].DNSNames) > 0 {
		for _, san := range manifest.CertificateChain[0].DNSNames {
			if san == tc.CommonName {
				validSubjectAlternativeName = true
			}
		}
	}

	if !validSubjectAlternativeName {
		return fmt.Errorf("invalid subject alternative name (san) from code signing certificate")
	}

	rootCertificatePool, err := util.GenerateCertificatePool(tc)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots:     rootCertificatePool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	_, err = manifest.CertificateChain[1].Verify(opts)
	if err != nil {
		return fmt.Errorf("error validating code signing certificate validity: %s", err)
	}
	return nil
}
