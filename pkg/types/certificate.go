package types

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"

	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

type SigningRequest struct {
	CSR          *bytes.Buffer
	PrivateKey   *pem.Block
	EncodedPKCS8 []byte
}

type SignedCertificate struct {
	CertificatePath                  string
	IntermediateCertificateChainPath string
	RootCertificateChainPath         string
}

type PublicKeyAlgorithm struct {
	Algorithm        x509.PublicKeyAlgorithm
	KeySize          map[int]interface{}
	Signature        map[string]bool
	SigningAlgorithm map[x509.SignatureAlgorithm]bool
}

var PublicKeyAlgorithms = map[KeyType]PublicKeyAlgorithm{
	RSA: {
		Algorithm: x509.RSA,
		KeySize: map[int]interface{}{
			2048: true,
			4096: true,
		},
		Signature: map[string]bool{
			"SHA256WITHRSA":    true,
			"SHA384WITHRSA":    true,
			"SHA512WITHRSA":    true,
			"SHA256WITHRSAPSS": true,
			"SHA384WITHRSAPSS": true,
			"SHA512WithRSAPSS": true,
		},
		SigningAlgorithm: map[x509.SignatureAlgorithm]bool{
			x509.SHA256WithRSA:    true,
			x509.SHA384WithRSA:    true,
			x509.SHA512WithRSA:    true,
			x509.SHA256WithRSAPSS: true,
			x509.SHA384WithRSAPSS: true,
			x509.SHA512WithRSAPSS: true,
		},
	},
	ECDSA: {
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
	Ed25519: {
		Algorithm: x509.Ed25519,
		KeySize: map[int]interface{}{
			256: true,
		},
	},
}

var PublicKeyAlgorithmStrings = map[string]PublicKeyAlgorithm{
	RSA.String(): {
		Algorithm: x509.RSA,
		KeySize: map[int]interface{}{
			2048: true,
			4096: true,
		},
		Signature: map[string]bool{
			"SHA256WITHRSA":    true,
			"SHA384WITHRSA":    true,
			"SHA512WITHRSA":    true,
			"SHA256WITHRSAPSS": true,
			"SHA384WITHRSAPSS": true,
			"SHA512WithRSAPSS": true,
		},
		SigningAlgorithm: map[x509.SignatureAlgorithm]bool{
			x509.SHA256WithRSA:    true,
			x509.SHA384WithRSA:    true,
			x509.SHA512WithRSA:    true,
			x509.SHA256WithRSAPSS: true,
			x509.SHA384WithRSAPSS: true,
			x509.SHA512WithRSAPSS: true,
		},
	},
	ECDSA.String(): {
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
	Ed25519.String(): {
		Algorithm: x509.Ed25519,
		KeySize: map[int]interface{}{
			256: true,
		},
	},
}

type SigningAlgorithm struct {
	Common x509.SignatureAlgorithm
	PCA    types.SigningAlgorithm
}

var ValidSignatures = map[string]SigningAlgorithm{
	"SHA256WITHECDSA": {
		Common: x509.ECDSAWithSHA256,
		PCA:    types.SigningAlgorithmSha256withecdsa,
	},
	"SHA384WITHECDSA": {
		Common: x509.ECDSAWithSHA384,
		PCA:    types.SigningAlgorithmSha384withecdsa,
	},
	"SHA512WITHECDSA": {
		Common: x509.ECDSAWithSHA512,
		PCA:    types.SigningAlgorithmSha512withecdsa,
	},
	"SHA256WITHRSA": {
		Common: x509.SHA256WithRSA,
		PCA:    types.SigningAlgorithmSha256withrsa,
	},
	"SHA384WITHRSA": {
		Common: x509.SHA384WithRSA,
		PCA:    types.SigningAlgorithmSha384withrsa,
	},
	"SHA512WITHRSA": {
		Common: x509.SHA512WithRSA,
		PCA:    types.SigningAlgorithmSha512withrsa,
	},
	// TODO: Support Probabilistic Element to the Signature Scheme [SHA256WithRSAPSS]
}
