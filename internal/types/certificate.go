package types

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

var SubordinatePath string

type CertificateParameters struct {
	Region     string
	CaArn      string
	AssumeRole bool
	RoleArn    string
	Validity   int
	RootCa     bool
}

type Extensions struct {
	KeyUsage         x509.KeyUsage
	ExtendedKeyUsage []x509.ExtKeyUsage
	TemplateArn      string
}

type Algorithm struct {
	Algorithm        x509.PublicKeyAlgorithm
	KeySize          map[int]any
	Signature        map[string]bool
	SigningAlgorithm map[x509.SignatureAlgorithm]bool
}

type SignatureAlgorithm struct {
	Common x509.SignatureAlgorithm
	PCA    types.SigningAlgorithm
}

type SigningRequest struct {
	CSR        *bytes.Buffer
	PrivateKey *pem.Block
}

type SignedCertificate struct {
	CertificatePath                  string
	IntermediateCertificateChainPath string
	RootCertificateChainPath         string
}

type CertificateMetadata struct {
	SerialNumber            string
	CommonName              string
	SubjectAlternativeName  []string
	ExpirationDate          time.Time
	IssuedDate              time.Time
	CaSerialNumber          string
	CertificateAuthorityArn string
	Revoked                 bool
	RevokedBy               string
	RevokeDate              time.Time
}

type CertificateRequest struct {
	CommonName            string
	SubjectAlternateNames []string
	DistinguishedName     DistinguishedName
	SigningAlgorithm      x509.SignatureAlgorithm
	PublicKeyAlgorithm    x509.PublicKeyAlgorithm
	KeySize               int
	Output                Output
}

type Output struct {
	CertificateSigningRequest string
	Certificate               string
	CertificateChain          string
	PrivateKey                string
}

type DistinguishedName struct {
	Country            []string
	Province           []string
	Locality           []string
	Organization       []string
	OrganizationalUnit []string
}

type EC2InstanceMetadata struct {
	InstanceIdentityDocument  []byte `json:"instance_identity_document"`
	InstanceIdentitySignature []byte `json:"instance_identity_signature"`
}

type CertificateAuthority struct {
	Certificate             *x509.Certificate
	AsymmetricKey           *AsymmetricKey
	SerialNumber            string
	CertificateAuthorityArn string
}

type AsymmetricKey interface {
	KeyPair() any
	Sign(data []byte) ([]byte, error)
}

var ValidSignatures = map[string]SignatureAlgorithm{
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

var PublicKeyAlgorithms = map[string]Algorithm{
	"RSA": {
		Algorithm: x509.RSA,
		KeySize: map[int]any{
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
		KeySize: map[int]any{
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
		KeySize: map[int]any{
			256: true,
		},
	},
}

var CertificateRequestExtension = map[string]Extensions{
	"EndEntityClientAuthCertificate": {
		KeyUsage:         x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		TemplateArn:      "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1",
	},
	"EndEntityServerAuthCertificate": {
		KeyUsage:         x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		TemplateArn:      "arn:aws:acm-pca:::template/EndEntityServerAuthCertificate/V1",
	},
	"CodeSigningCertificate": {
		KeyUsage:         x509.KeyUsageDigitalSignature,
		ExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		TemplateArn:      "arn:aws:acm-pca:::template/CodeSigningCertificate/V1",
	},
}

var ValidNodeAttestation = map[string]bool{
	"None": false,
	"AWS":  true,
}
