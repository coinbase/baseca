package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/coinbase/baseca/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCSR(t *testing.T) {
	csr := types.CertificateRequest{
		PublicKeyAlgorithm: x509.RSA,
		KeySize:            2048,
		SigningAlgorithm:   x509.SHA256WithRSA,
		CommonName:         "example.com",
		DistinguishedName: types.DistinguishedName{
			Country:  []string{"US"},
			Province: []string{"CA"},
		},
		SubjectAlternateNames: []string{"www.example.com", "sub.example.com"},
		Output: types.Output{
			CertificateSigningRequest: "/tmp/unit_test_csr.pem",
			PrivateKey:                "/tmp/unit_test_pk.pem",
		},
	}

	// Generate CSR with RSA Key Pair
	rsaSigningRequest, err := GenerateCSR(csr)
	assert.NoError(t, err)
	assert.NotNil(t, rsaSigningRequest)

	assert.Contains(t, string(rsaSigningRequest.CSR.String()), "CERTIFICATE REQUEST")
	assert.Contains(t, string(pem.EncodeToMemory(rsaSigningRequest.PrivateKey)), "RSA PRIVATE KEY")

	// Create an ECDSA CertificateRequest
	ecdsaCsr := types.CertificateRequest{
		PublicKeyAlgorithm: x509.ECDSA,
		KeySize:            256,
		SigningAlgorithm:   x509.ECDSAWithSHA512,
		CommonName:         "example.com",
		DistinguishedName: types.DistinguishedName{
			Country:  []string{"US"},
			Province: []string{"CA"},
		},
		SubjectAlternateNames: []string{"www.example.com", "sub.example.com"},
		Output: types.Output{
			CertificateSigningRequest: "/tmp/unit_test_csr.pem",
			PrivateKey:                "/tmp/unit_test_pk.pem",
		},
	}

	// Generate the CSR with ECDSA Key Pair
	ecdsaSigningRequest, err := GenerateCSR(ecdsaCsr)
	assert.NoError(t, err)
	assert.NotNil(t, ecdsaSigningRequest)

	assert.Contains(t, string(ecdsaSigningRequest.CSR.String()), "CERTIFICATE REQUEST")
	assert.Contains(t, string(pem.EncodeToMemory(ecdsaSigningRequest.PrivateKey)), "EC PRIVATE KEY")
}
