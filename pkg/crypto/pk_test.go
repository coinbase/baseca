package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestRSASign(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	rsaKey := &RSA{
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	}
	data := []byte("_example")
	signature, err := rsaKey.Sign(data)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}
	if len(signature) == 0 {
		t.Fatalf("expected non-empty signature")
	}
}

func TestECDSASign(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	ecdsaKey := &ECDSA{
		PublicKey:  &privateKey.PublicKey,
		PrivateKey: privateKey,
	}
	data := []byte("_example")
	signature, err := ecdsaKey.Sign(data)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}
	if len(signature) == 0 {
		t.Fatalf("expected non-empty signature")
	}
}

func TestReturnPrivateKey(t *testing.T) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa private key: %v", err)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa private key: %v", err)
	}

	tests := []struct {
		key      AsymmetricKey
		expected interface{}
	}{
		{&RSA{PrivateKey: rsaPrivateKey}, rsaPrivateKey},
		{&ECDSA{PrivateKey: ecdsaPrivateKey}, ecdsaPrivateKey},
		{nil, nil},
	}

	for _, test := range tests {
		got, err := ReturnPrivateKey(test.key)
		if err != nil && test.key != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, test.expected) {
			t.Errorf("expected %v, but got %v", test.expected, got)
		}
	}
}

func TestCertificateAuthorityInitialization(t *testing.T) {
	ca := &CertificateAuthority{
		SerialNumber: "0000000000",
	}
	if ca.SerialNumber != "0000000000" {
		t.Errorf("expected serial number to be '0000000000', but got '%s'", ca.SerialNumber)
	}
}
