package crypto

import (
	"crypto/x509"
	"testing"
)

func TestSigningRequestGeneratorRSA(t *testing.T) {
	r := &SigningRequestGeneratorRSA{
		Size: 2048,
	}

	key, err := r.Generate()
	if err != nil {
		t.Fatalf("error generating rsa private key: %v", err)
	}

	if keyType := r.KeyType(); keyType != "RSA PRIVATE KEY" {
		t.Errorf("RSA PRIVATE KEY does not exist within private key")

	}

	if !r.SupportsPublicKeyAlgorithm(x509.RSA) {
		t.Errorf("rsa public key algorithm not supported")
	}

	if !r.SupportsSigningAlgorithm(x509.SHA256WithRSA) {
		t.Errorf("SHA256WithRSA signing algorithm not supported")
	}

	if !r.SupportsKeySize(2048) {
		t.Errorf("rsa key size not supported")
	}

	_, err = r.MarshalPrivateKey(key)
	if err != nil {
		t.Errorf("error marshaling rsa private key: %v", err)
	}
}

func TestSigningRequestGeneratorECDSA(t *testing.T) {
	e := &SigningRequestGeneratorECDSA{
		Curve: 256,
	}

	key, err := e.Generate()
	if err != nil {
		t.Fatalf("error generating ecdsa private key: %v", err)
	}

	if keyType := e.KeyType(); keyType != "EC PRIVATE KEY" {
		t.Errorf("EC PRIVATE KEY does not exist within private key")
	}

	if !e.SupportsPublicKeyAlgorithm(x509.ECDSA) {
		t.Errorf("ecdsa public key algorithm not supported")
	}

	if !e.SupportsSigningAlgorithm(x509.ECDSAWithSHA256) {
		t.Errorf("ECDSAWithSHA256 signing algorithm not supported")
	}

	if !e.SupportsKeySize(256) {
		t.Errorf("ecdsa curve size not supported")
	}

	_, err = e.MarshalPrivateKey(key)
	if err != nil {
		t.Errorf("error marshaling ecdsa private key: %v", err)
	}
}
