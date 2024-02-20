package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"

	"github.com/coinbase/baseca/pkg/types"
)

type RSASigner struct {
	PrivateKey         *rsa.PrivateKey
	SignatureAlgorithm x509.SignatureAlgorithm
	Hash               func() (hash.Hash, crypto.Hash)
}

type ECDSASigner struct {
	PrivateKey         *ecdsa.PrivateKey
	SignatureAlgorithm x509.SignatureAlgorithm
	Hash               func() (hash.Hash, crypto.Hash)
}

func (r *RSASigner) Sign(hashedData []byte) ([]byte, error) {
	_, cryptoHash := r.Hash()
	switch r.SignatureAlgorithm {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return rsa.SignPSS(rand.Reader, r.PrivateKey, cryptoHash, hashedData, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	default:
		return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, cryptoHash, hashedData)
	}
}

func (e *ECDSASigner) Sign(hashedData []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, e.PrivateKey, hashedData)
}

func EncodeToPKCS8(pkBlock *pem.Block) (*pem.Block, error) {
	var key interface{}
	var err error

	switch pkBlock.Type {
	case types.RSA_PRIVATE_KEY.String():
		key, err = x509.ParsePKCS1PrivateKey(pkBlock.Bytes)
	case types.ECDSA_PRIVATE_KEY.String():
		key, err = x509.ParseECPrivateKey(pkBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %s", pkBlock.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to PKCS#8: %v", err)
	}

	pkcs8Encoding := &pem.Block{
		Type:  types.PKCS8_PRIVATE_KEY.String(), // PKCS#8 Encoding
		Bytes: pkcs8Bytes,
	}

	return pkcs8Encoding, nil
}

func ReturnSignerInterface(pkBlock *pem.Block) (crypto.Signer, error) {
	var key interface{}
	var err error

	switch pkBlock.Type {
	case types.RSA_PRIVATE_KEY.String():
		key, err = x509.ParsePKCS1PrivateKey(pkBlock.Bytes)
	case types.ECDSA_PRIVATE_KEY.String():
		key, err = x509.ParseECPrivateKey(pkBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %s", pkBlock.Type)
	}

	var signer crypto.Signer
	var ok bool

	if signer, ok = key.(crypto.Signer); !ok {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	return signer, nil
}
