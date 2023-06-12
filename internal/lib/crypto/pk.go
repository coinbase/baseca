package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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

func ReturnPrivateKey(key types.AsymmetricKey) (interface{}, error) {
	switch k := key.KeyPair().(type) {
	case *RSA:
		return k.PrivateKey, nil
	case *ECDSA:
		return k.PrivateKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func GenerateCSR(csr types.CertificateRequest) (*types.SigningRequest, error) {
	switch csr.PublicKeyAlgorithm {
	case x509.RSA:
		if csr.KeySize < 2048 {
			return nil, errors.New("invalid key size, rsa minimum valid bits 2048]")
		}
		// TODO: ECDSA
	}

	subject := pkix.Name{
		CommonName:         csr.CommonName,
		Country:            csr.DistinguishedName.Country,
		Province:           csr.DistinguishedName.Province,
		Locality:           csr.DistinguishedName.Locality,
		Organization:       csr.DistinguishedName.Organization,
		OrganizationalUnit: csr.DistinguishedName.OrganizationalUnit,
	}

	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: csr.SigningAlgorithm,
		DNSNames:           csr.SubjectAlternateNames,
	}

	switch csr.SigningAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		pk, err := rsa.GenerateKey(rand.Reader, csr.KeySize)
		if err != nil {
			return nil, errors.New("error generating rsa key pair")
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, pk)
		if err != nil {
			return nil, err
		}

		certificatePem := new(bytes.Buffer)
		err = pem.Encode(certificatePem, &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})

		if err != nil {
			return nil, errors.New("error encoding certificate request (csr)")
		}

		if len(csr.Output.CertificateSigningRequest) != 0 {
			if err := os.WriteFile(csr.Output.CertificateSigningRequest, certificatePem.Bytes(), os.ModePerm); err != nil {
				return nil, fmt.Errorf("error writing certificate signing request (csr) to [%s]", csr.Output.CertificateSigningRequest)
			}
		}

		pkBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pk),
		}

		if len(csr.Output.PrivateKey) != 0 {
			if err := os.WriteFile(csr.Output.PrivateKey, pem.EncodeToMemory(pkBlock), os.ModePerm); err != nil {
				return nil, fmt.Errorf("error writing private key to [%s]", csr.Output.PrivateKey)
			}
		}

		return &types.SigningRequest{
			CSR:        certificatePem,
			PrivateKey: pkBlock,
		}, nil
	default:
		return nil, errors.New("unsupported signing algorithm")
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
