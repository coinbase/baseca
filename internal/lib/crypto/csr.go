package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/coinbase/baseca/internal/types"
)

func GenerateCSR(csr types.CertificateRequest) (*types.SigningRequest, error) {
	var generator CSRGenerator

	switch csr.PublicKeyAlgorithm {
	case x509.RSA:
		if _, ok := types.PublicKeyAlgorithms["RSA"].KeySize[csr.KeySize]; !ok {
			return nil, fmt.Errorf("rsa invalid key size %d", csr.KeySize)
		}
		if _, ok := types.PublicKeyAlgorithms["RSA"].SigningAlgorithm[csr.SigningAlgorithm]; !ok {
			return nil, fmt.Errorf("rsa invalid signing algorithm %s", csr.SigningAlgorithm)
		}
		generator = &SigningRequestGeneratorRSA{Size: csr.KeySize}
	case x509.ECDSA:
		if _, ok := types.PublicKeyAlgorithms["ECDSA"].KeySize[csr.KeySize]; !ok {
			return nil, fmt.Errorf("ecdsa invalid key size %d", csr.KeySize)
		}
		if _, ok := types.PublicKeyAlgorithms["ECDSA"].SigningAlgorithm[csr.SigningAlgorithm]; !ok {
			return nil, fmt.Errorf("ecdsa invalid signing algorithm %s", csr.SigningAlgorithm)
		}
		generator = &SigningRequestGeneratorECDSA{Curve: csr.KeySize}
	default:
		return nil, fmt.Errorf("unsupported public key algorithm")
	}

	pk, err := generator.Generate()
	if err != nil {
		return nil, fmt.Errorf("error generating private key [%s]: %w", generator.KeyType(), err)
	}

	subject := pkix.Name{
		CommonName:         csr.CommonName,
		Country:            csr.DistinguishedName.Country,
		Province:           csr.DistinguishedName.Province,
		Locality:           csr.DistinguishedName.Locality,
		Organization:       csr.DistinguishedName.Organization,
		OrganizationalUnit: csr.DistinguishedName.OrganizationalUnit,
	}

	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: csr.SigningAlgorithm,
		DNSNames:           csr.SubjectAlternateNames,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, pk)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate request: %w", err)
	}

	certificatePem := new(bytes.Buffer)
	err = pem.Encode(certificatePem, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	if err != nil {
		return nil, fmt.Errorf("error encoding certificate request (csr): %w", err)
	}

	if len(csr.Output.CertificateSigningRequest) != 0 {
		if err := writeFileToSystem(csr.Output.CertificateSigningRequest, certificatePem.Bytes()); err != nil {
			return nil, fmt.Errorf("error writing certificate signing request (csr) to [%s]: %w", csr.Output.CertificateSigningRequest, err)
		}
	}

	pkBytes, err := generator.MarshalPrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("error marshaling private key: %w", err)
	}

	pkBlock := &pem.Block{
		Type:  generator.KeyType(),
		Bytes: pkBytes,
	}

	if len(csr.Output.PrivateKey) != 0 {
		if err := writeFileToSystem(csr.Output.PrivateKey, pem.EncodeToMemory(pkBlock)); err != nil {
			return nil, fmt.Errorf("error writing private key to [%s]: %w", csr.Output.PrivateKey, err)
		}
	}

	return &types.SigningRequest{
		CSR:        certificatePem,
		PrivateKey: pkBlock,
	}, nil
}
