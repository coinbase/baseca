package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/coinbase/baseca/internal/types"
)

type CSRGenerator interface {
	Generate() (crypto.PrivateKey, error)
	KeyType() string
	MarshalPrivateKey(key crypto.PrivateKey) ([]byte, error)
	SupportsPublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm) bool
	SupportsSigningAlgorithm(algorithm x509.SignatureAlgorithm) bool
	SupportsKeySize(size int) bool
}

type SigningRequestGeneratorRSA struct {
	Size int
}

type SigningRequestGeneratorECDSA struct {
	Curve int
}

// RSA Interface
func (r *SigningRequestGeneratorRSA) Generate() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, r.Size)
}

func (r *SigningRequestGeneratorRSA) KeyType() string {
	return "RSA PRIVATE KEY"
}

func (r *SigningRequestGeneratorRSA) MarshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)), nil
}

func (r *SigningRequestGeneratorRSA) SupportsPublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm) bool {
	return algorithm == x509.RSA
}

func (r *SigningRequestGeneratorRSA) SupportsSigningAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	_, ok := types.PublicKeyAlgorithms["RSA"].SigningAlgorithm[algorithm]
	return ok
}

func (r *SigningRequestGeneratorRSA) SupportsKeySize(size int) bool {
	_, ok := types.PublicKeyAlgorithms["RSA"].KeySize[size]
	return ok
}

// ECDSA Interface
func (e *SigningRequestGeneratorECDSA) Generate() (crypto.PrivateKey, error) {
	c, ok := types.PublicKeyAlgorithms["ECDSA"].KeySize[e.Curve]

	if !ok {
		return nil, fmt.Errorf("ecdsa curve [%d] not supported", e.Curve)
	}

	curve, ok := c.(elliptic.Curve)
	if !ok {
		return nil, fmt.Errorf("invalid elliptic.Curve type")
	}

	return ecdsa.GenerateKey(curve, rand.Reader)
}

func (e *SigningRequestGeneratorECDSA) KeyType() string {
	return "EC PRIVATE KEY"
}

func (e *SigningRequestGeneratorECDSA) MarshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
}

func (e *SigningRequestGeneratorECDSA) SupportsPublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm) bool {
	return algorithm == x509.ECDSA
}

func (e *SigningRequestGeneratorECDSA) SupportsSigningAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	_, ok := types.PublicKeyAlgorithms["ECDSA"].SigningAlgorithm[algorithm]
	return ok
}

func (e *SigningRequestGeneratorECDSA) SupportsKeySize(size int) bool {
	_, ok := types.PublicKeyAlgorithms["ECDSA"].KeySize[size]
	return ok
}
