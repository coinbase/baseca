package baseca

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/coinbase/baseca/pkg/crypto"
	"github.com/coinbase/baseca/pkg/types"
)

func GenerateCSR(csr types.CertificateRequest) (*types.SigningRequest, error) {
	var generator crypto.CSRGenerator

	switch csr.PublicKeyAlgorithm {
	case x509.RSA:
		if _, ok := types.PublicKeyAlgorithms[types.RSA].KeySize[csr.KeySize]; !ok {
			return nil, fmt.Errorf("rsa invalid key size %d", csr.KeySize)
		}
		if _, ok := types.PublicKeyAlgorithms[types.RSA].SigningAlgorithm[csr.SigningAlgorithm]; !ok {
			return nil, fmt.Errorf("rsa invalid signing algorithm %s", csr.SigningAlgorithm)
		}
		generator = &crypto.SigningRequestGeneratorRSA{Size: csr.KeySize}
	case x509.ECDSA:
		if _, ok := types.PublicKeyAlgorithms[types.ECDSA].KeySize[csr.KeySize]; !ok {
			return nil, fmt.Errorf("ecdsa invalid curve %d", csr.KeySize)
		}
		if _, ok := types.PublicKeyAlgorithms[types.ECDSA].SigningAlgorithm[csr.SigningAlgorithm]; !ok {
			return nil, fmt.Errorf("ecdsa invalid signing algorithm %s", csr.SigningAlgorithm)
		}
		generator = &crypto.SigningRequestGeneratorECDSA{Curve: csr.KeySize}
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
		StreetAddress:      csr.DistinguishedName.StreetAddress,
		PostalCode:         csr.DistinguishedName.PostalCode,
		SerialNumber:       csr.DistinguishedName.SerialNumber,
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
		Type:  types.CERTIFICATE_REQUEST.String(),
		Bytes: csrBytes,
	})

	if err != nil {
		return nil, fmt.Errorf("error encoding certificate request (csr): %w", err)
	}

	if len(csr.Output.CertificateSigningRequest) != 0 {
		if err := os.WriteFile(csr.Output.CertificateSigningRequest, certificatePem.Bytes(), os.ModePerm); err != nil {
			return nil, fmt.Errorf("error writing certificate signing request (csr) to [%s]", csr.Output.CertificateSigningRequest)
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

	pkcs8Encoding, err := crypto.EncodeToPKCS8(pkBlock)
	if err != nil {
		return nil, fmt.Errorf("error converting private key to pkcs8: %w", err)
	}

	if len(csr.Output.PrivateKey) != 0 {
		if err := os.WriteFile(csr.Output.PrivateKey, pem.EncodeToMemory(pkBlock), os.ModePerm); err != nil {
			return nil, fmt.Errorf("error writing private key to [%s]", csr.Output.PrivateKey)
		}
	}

	return &types.SigningRequest{
		CSR:          certificatePem,
		PrivateKey:   pkBlock,
		EncodedPKCS8: pem.EncodeToMemory(pkcs8Encoding),
	}, nil
}
