package baseca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/coinbase/baseca/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCSR(t *testing.T) {
	csr := CertificateRequest{
		PublicKeyAlgorithm: x509.RSA,
		KeySize:            2048,
		SigningAlgorithm:   x509.SHA256WithRSA,
		CommonName:         "example.com",
		DistinguishedName: DistinguishedName{
			Country:  []string{"US"},
			Province: []string{"CA"},
		},
		SubjectAlternateNames: []string{"www.example.com", "subordinate.example.com"},
		Output: Output{
			CertificateSigningRequest: "/tmp/csr.pem",
			PrivateKey:                "/tmp/pk.pem",
		},
	}

	// Generate CSR with RSA Key Pair
	rsaSigningRequest, err := GenerateCSR(csr)
	assert.NoError(t, err)
	assert.NotNil(t, rsaSigningRequest)

	assert.Contains(t, string(rsaSigningRequest.CSR.String()), types.CERTIFICATE_REQUEST.String())
	assert.Contains(t, string(pem.EncodeToMemory(rsaSigningRequest.PrivateKey)), types.RSA_PRIVATE_KEY.String())

	// Create an ECDSA CertificateRequest
	ecdsaCsr := CertificateRequest{
		PublicKeyAlgorithm: x509.ECDSA,
		KeySize:            256,
		SigningAlgorithm:   x509.ECDSAWithSHA512,
		CommonName:         "example.com",
		DistinguishedName: DistinguishedName{
			Country:  []string{"US"},
			Province: []string{"CA"},
		},
		SubjectAlternateNames: []string{"www.example.com", "subordinate.example.com"},
		Output: Output{
			CertificateSigningRequest: "/tmp/csr.pem",
			PrivateKey:                "/tmp/pk.pem",
		},
	}

	// Generate the CSR with ECDSA Key Pair
	ecdsaSigningRequest, err := GenerateCSR(ecdsaCsr)
	assert.NoError(t, err)
	assert.NotNil(t, ecdsaSigningRequest)

	assert.Contains(t, string(ecdsaSigningRequest.CSR.String()), types.CERTIFICATE_REQUEST.String())
	assert.Contains(t, string(pem.EncodeToMemory(ecdsaSigningRequest.PrivateKey)), types.ECDSA_PRIVATE_KEY.String())
}
