package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coinbase/baseca/internal/types"
)

type RSA struct {
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

type ECDSA struct {
	PublicKey  *ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
}

func (key *RSA) KeyPair() any {
	return key
}

func (key *RSA) Sign(data []byte) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, hashed)
}

func (key *ECDSA) KeyPair() any {
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

func ReturnPrivateKey(key types.AsymmetricKey) (any, error) {
	switch k := key.KeyPair().(type) {
	case *RSA:
		return k.PrivateKey, nil
	case *ECDSA:
		return k.PrivateKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func GetSubordinateCaParameters(service string) (*types.CertificateAuthority, error) {
	subordinatePath := filepath.Join(types.SubordinatePath, service+_subordinateCertificate)
	subordinate, err := readFileFromSystem(subordinatePath)
	if err != nil {
		return nil, fmt.Errorf("error reading subordinate ca from %s: %w", subordinatePath, err)
	}

	subordinatePem, _ := pem.Decode(*subordinate)
	if subordinatePem == nil {
		return nil, fmt.Errorf("error decoding subordinate PEM")
	}

	subordinateCertificate, err := x509.ParseCertificate(subordinatePem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing subordinate certificate: %w", err)
	}

	privateKeyPath := filepath.Join(types.SubordinatePath, service+_subordinatePrivateKey)
	pk, err := readFileFromSystem(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading subordinate ca key from %s: %w", privateKeyPath, err)
	}

	pkPem, _ := pem.Decode(*pk)
	if pkPem == nil {
		return nil, fmt.Errorf("error decoding private key")
	}

	subordinatePrivateKey, err := formatAsymmetricKey(pkPem)
	if err != nil {
		return nil, fmt.Errorf("error formatting private key: %w", err)
	}

	serialNumberPath := filepath.Join(types.SubordinatePath, service+_subordinateSerialNumber)
	caSerialNumber, err := readFileFromSystem(serialNumberPath)
	if err != nil {
		return nil, fmt.Errorf("error reading subordinate ca serial number from %s: %w", serialNumberPath, err)
	}

	caArnPath := filepath.Join(types.SubordinatePath, service+_certificateAuthorityArn)
	caArn, err := readFileFromSystem(caArnPath)
	if err != nil {
		return nil, fmt.Errorf("error reading subordinate ca arn from %s: %w", caArnPath, err)
	}

	return &types.CertificateAuthority{
		Certificate:             subordinateCertificate,
		AsymmetricKey:           &subordinatePrivateKey,
		SerialNumber:            string(*caSerialNumber),
		CertificateAuthorityArn: string(*caArn),
	}, nil
}

func readFileFromSystem(path string) (*[]byte, error) {
	if !strings.HasPrefix(path, types.SubordinatePath) {
		return nil, fmt.Errorf("unsafe file input path")
	}

	file, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return &file, err
}

func writeFileToSystem(path string, data []byte) error {
	if !strings.HasPrefix(path, types.SubordinatePath) {
		return fmt.Errorf("unsafe file input, write private key")
	}

	if err := os.WriteFile(path, data, os.ModePerm); err != nil {
		return err
	}
	return nil
}

func formatAsymmetricKey(block *pem.Block) (types.AsymmetricKey, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err := parseRSAPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsaKey, nil
	case "EC PRIVATE KEY":
		ecdsaKey, err := parseECDSAPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return ecdsaKey, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

func parseRSAPrivateKey(keyBytes []byte) (*RSA, error) {
	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	rsaPrivateKey := &RSA{
		PublicKey:  &key.PublicKey,
		PrivateKey: key,
	}
	return rsaPrivateKey, nil
}

func parseECDSAPrivateKey(keyBytes []byte) (*ECDSA, error) {
	key, err := x509.ParseECPrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	ecdsaPrivateKey := &ECDSA{
		PublicKey:  &key.PublicKey,
		PrivateKey: key,
	}
	return ecdsaPrivateKey, nil
}
