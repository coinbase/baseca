package baseca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/coinbase/baseca/pkg/types"
)

func TestValidateSignature(t *testing.T) {
	tests := []struct {
		name     string
		validate func() error
		check    func(t *testing.T, err error)
	}{
		{
			name: "Valid Signature RSA",
			validate: func() error {
				data := []byte("_value")
				pk, certificate, path := generateSelfSignedCertificateAuthority()
				signer, _ := parsePrivateKey(pk, x509.SHA256WithRSA)

				signature, err := signer.Sign(data)
				if err != nil {
					return fmt.Errorf("error signing data: %s", err)
				}

				c, err := x509.ParseCertificate(certificate)
				if err != nil {
					return fmt.Errorf("error parsing code signing certificate: %s", err)
				}

				tc := types.TrustChain{
					CommonName: "example.coinbase.com",
					CertificateAuthorityFiles: []string{
						path.Name(),
					},
				}

				manifest := types.Manifest{
					CertificateChain: []*x509.Certificate{c},
					Signature:        &signature,
					SigningAlgorithm: x509.SHA256WithRSA,
					Data: types.Data{
						Raw: &data,
					},
				}
				return ValidateSignature(tc, manifest)
			},
			check: func(t *testing.T, err error) {
				if err != nil {
					t.Errorf("expected no error, got %s", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.validate()
			tc.check(t, err)
		})
	}
}

func generateSelfSignedCertificateAuthority() ([]byte, []byte, *os.File) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "example.coinbase.com",
			Organization: []string{"Coinbase"},
		},
		DNSNames:  []string{"example.coinbase.com"},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Generate DER Encoded Self-Signed Certificate
	certificate, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	// PKCS#8 Encode Private Key
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	pk := pem.EncodeToMemory(&pem.Block{Type: types.PKCS8_PRIVATE_KEY.String(), Bytes: pkcs8Bytes})

	// Use Self-Signed Certificate as Certificate Authority
	path, err := os.CreateTemp("", "ca.crt")
	if err != nil {
		panic(err)
	}
	defer path.Close()
	_ = pem.Encode(path, &pem.Block{Type: types.CERTIFICATE.String(), Bytes: certificate})

	return pk, certificate, path
}
