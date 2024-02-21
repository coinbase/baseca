package baseca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"log"
	"testing"

	"github.com/coinbase/baseca/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestParsePrivateKey(t *testing.T) {
	tests := []struct {
		name      string
		pk        func() []byte
		algorithm x509.SignatureAlgorithm
		check     func(t *testing.T, err error)
	}{
		{
			name: "Valid RSA",
			pk: func() []byte {
				return GENERATE_PKCS8_RSA()
			},
			algorithm: x509.SHA256WithRSA,
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Valid ECDSA",
			pk: func() []byte {
				return GENERATE_PKCS8_ECDSA()
			},
			algorithm: x509.ECDSAWithSHA256,
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Invalid Signing Algorithm",
			pk: func() []byte {
				return GENERATE_PKCS8_RSA()
			},
			algorithm: x509.DSAWithSHA1,
			check: func(t *testing.T, err error) {
				require.EqualError(t, err, "invalid signing algorithm: DSA-SHA1")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePrivateKey(tc.pk(), tc.algorithm)
			tc.check(t, err)
		})
	}
}

func TestSign(t *testing.T) {
	tests := []struct {
		name  string
		sign  func() ([]byte, error)
		check func(t *testing.T, err error)
	}{
		{
			name: "Valid RSA Signer",
			sign: func() ([]byte, error) {
				signer, err := parsePrivateKey(GENERATE_PKCS8_RSA(), x509.SHA256WithRSA)
				if err != nil {
					return nil, err
				}
				hasher := sha256.New()
				hasher.Write([]byte("_value"))
				return signer.Sign(hasher.Sum(nil))
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Valid ECDSA Signer",
			sign: func() ([]byte, error) {
				signer, err := parsePrivateKey(GENERATE_PKCS8_ECDSA(), x509.ECDSAWithSHA256)
				if err != nil {
					return nil, err
				}
				hasher := sha256.New()
				hasher.Write([]byte("_value"))
				return signer.Sign(hasher.Sum(nil))
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.sign()
			tc.check(t, err)
		})
	}
}

func GENERATE_PKCS8_RSA() []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key to PKCS#8: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  types.PKCS8_PRIVATE_KEY.String(), // PKCS#8 Encoding
		Bytes: pkcs8Bytes,
	}
	return pem.EncodeToMemory(pemBlock)
}

func GENERATE_PKCS8_ECDSA() []byte {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA private key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal ECDSA private key to PKCS#8: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  types.PKCS8_PRIVATE_KEY.String(), // PKCS#8 Encoding
		Bytes: pkcs8Bytes,
	}
	return pem.EncodeToMemory(pemBlock)
}
