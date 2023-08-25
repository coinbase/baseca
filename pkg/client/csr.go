package baseca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

type SigningRequest struct {
	CSR        *bytes.Buffer
	PrivateKey *pem.Block
}

type SignedCertificate struct {
	CertificatePath                  string
	IntermediateCertificateChainPath string
	RootCertificateChainPath         string
}

func GenerateCSR(csr CertificateRequest) (*SigningRequest, error) {
	switch csr.PublicKeyAlgorithm {
	case x509.RSA:
		if csr.KeySize < 2048 {
			return nil, errors.New("invalid key size, rsa minimum valid bits 2048]")
		}
		// TODO: ECDSA
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

	switch csr.SigningAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		pk, err := rsa.GenerateKey(rand.Reader, csr.KeySize)
		if err != nil {
			return nil, errors.New("error generating rsa key pair")
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, pk)
		if err != nil {
			return nil, err
		}

		certificatePem := new(bytes.Buffer)
		err = pem.Encode(certificatePem, &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})

		if err != nil {
			return nil, errors.New("error encoding certificate request (csr)")
		}

		if len(csr.Output.CertificateSigningRequest) != 0 {
			if err := os.WriteFile(csr.Output.CertificateSigningRequest, certificatePem.Bytes(), os.ModePerm); err != nil {
				return nil, fmt.Errorf("error writing certificate signing request (csr) to [%s]", csr.Output.CertificateSigningRequest)
			}
		}

		pkBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pk),
		}

		if len(csr.Output.PrivateKey) != 0 {
			if err := os.WriteFile(csr.Output.PrivateKey, pem.EncodeToMemory(pkBlock), os.ModePerm); err != nil {
				return nil, fmt.Errorf("error writing private key to [%s]", csr.Output.PrivateKey)
			}
		}

		return &SigningRequest{
			CSR:        certificatePem,
			PrivateKey: pkBlock,
		}, nil

	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, errors.New("error generating ECDSA key pair")
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, pk)
		if err != nil {
			return nil, err
		}

		certificatePem := new(bytes.Buffer)
		err = pem.Encode(certificatePem, &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})

		if err != nil {
			return nil, errors.New("error encoding certificate request (csr)")
		}

		if len(csr.Output.CertificateSigningRequest) != 0 {
			if err := os.WriteFile(csr.Output.CertificateSigningRequest, certificatePem.Bytes(), os.ModePerm); err != nil {
				return nil, fmt.Errorf("error writing certificate signing request (csr) to [%s]", csr.Output.CertificateSigningRequest)
			}
		}

		ecPrivateKeyBytes, err := x509.MarshalECPrivateKey(pk)
		if err != nil {
			return nil, errors.New("error marshaling ECDSA private key")
		}

		pkBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecPrivateKeyBytes,
		}

		if len(csr.Output.PrivateKey) != 0 {
			if err := os.WriteFile(csr.Output.PrivateKey, pem.EncodeToMemory(pkBlock), os.ModePerm); err != nil {
				return nil, fmt.Errorf("error writing private key to [%s]", csr.Output.PrivateKey)
			}
		}

		return &SigningRequest{
			CSR:        certificatePem,
			PrivateKey: pkBlock,
		}, nil

	default:
		return nil, errors.New("unsupported signing algorithm")
	}
}
