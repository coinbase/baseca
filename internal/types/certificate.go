package types

import (
	"crypto/x509"
	"encoding/pem"
	"time"
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
	KeySize          map[int]interface{}
	Signature        map[string]bool
	SigningAlgorithm map[x509.SignatureAlgorithm]bool
}

type CertificateResponseData struct {
	Certificate                  string              `json:"certificate"`
	IntermediateCertificateChain string              `json:"intermediate_certificate_chain,omitempty"`
	RootCertificateChain         string              `json:"root_certificate_chain,omitempty"`
	Metadata                     CertificateMetadata `json:"metadata"`
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

type EC2InstanceMetadata struct {
	InstanceIdentityDocument  []byte `json:"instance_identity_document"`
	InstanceIdentitySignature []byte `json:"instance_identity_signature"`
}

type CertificateAuthority struct {
	Certificate             *x509.Certificate
	PrivateKey              *pem.Block
	SerialNumber            string
	CertificateAuthorityArn string
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
	"Local": false,
	"AWS":   true,
}
