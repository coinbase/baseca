package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

type CertificateAuthority struct {
	Certificate             *x509.Certificate
	AsymmetricKey           *AsymmetricKey
	SerialNumber            string
	CertificateAuthorityArn string
}

type AsymmetricKey interface {
	KeyPair() interface{}
	Sign(data []byte) ([]byte, error)
}

type RSA struct {
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

type ECDSA struct {
	PublicKey  *ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
}

func (key *RSA) KeyPair() interface{} {
	return key
}

func (key *RSA) Sign(data []byte) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, hashed)
}

func (key *ECDSA) KeyPair() interface{} {
	return key
}

func (key *ECDSA) Sign(data []byte) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, key.PrivateKey, hashed)
	if err != nil {
		return nil, err
	}
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

func ReturnPrivateKey(key AsymmetricKey) (interface{}, error) {
	if key == nil {
		return nil, fmt.Errorf("asymmetric key is nil")
	}

	switch k := key.KeyPair().(type) {
	case *RSA:
		return k.PrivateKey, nil
	case *ECDSA:
		return k.PrivateKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}
