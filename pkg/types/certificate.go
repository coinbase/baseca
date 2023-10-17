package types

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
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

type PublicKeyAlgorithm struct {
	Algorithm        x509.PublicKeyAlgorithm
	KeySize          map[int]any
	Signature        map[string]bool
	SigningAlgorithm map[x509.SignatureAlgorithm]bool
}

var PublicKeyAlgorithms = map[string]PublicKeyAlgorithm{
	"RSA": {
		Algorithm: x509.RSA,
		KeySize: map[int]interface{}{
			2048: true,
			4096: true,
		},
		Signature: map[string]bool{
			"SHA256WITHRSA": true,
			"SHA384WITHRSA": true,
			"SHA512WITHRSA": true,
		},
		SigningAlgorithm: map[x509.SignatureAlgorithm]bool{
			x509.SHA256WithRSA: true,
			x509.SHA384WithRSA: true,
			x509.SHA512WithRSA: true,
		},
	},
	"ECDSA": {
		Algorithm: x509.ECDSA,
		KeySize: map[int]interface{}{
			256: elliptic.P256(),
			384: elliptic.P384(),
			521: elliptic.P521(),
		},
		Signature: map[string]bool{
			"SHA256WITHECDSA": true,
			"SHA384WITHECDSA": true,
			"SHA512WITHECDSA": true,
		},
		SigningAlgorithm: map[x509.SignatureAlgorithm]bool{
			x509.ECDSAWithSHA256: true,
			x509.ECDSAWithSHA384: true,
			x509.ECDSAWithSHA512: true,
		},
	},
	// TODO: Support Ed25519
	"Ed25519": {
		Algorithm: x509.Ed25519,
		KeySize: map[int]interface{}{
			256: true,
		},
	},
}
