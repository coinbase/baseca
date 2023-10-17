package types

import "crypto/x509"

type TrustChain struct {
	CommonName                    string
	CertificateAuthorityDirectory []string
	CertificateAuthorityFiles     []string
}

type Manifest struct {
	CertificateChain []*x509.Certificate
	Signature        []byte
	Data             []byte
	SigningAlgorithm x509.SignatureAlgorithm
}
