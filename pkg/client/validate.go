package baseca

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/coinbase/baseca/pkg/types"
)

// Signature Validation for Different Data Inputs
func ValidateSignature(tc types.TrustChain, manifest types.Manifest) error {
	err := validateManifestParameters(manifest)
	if err != nil {
		return fmt.Errorf("[manifest] %w", err)
	}

	// Priority of Data Inputs (Path, Reader, Raw)
	switch {
	case manifest.Data.Path != types.Path{}:
		err := validateStreamedSignature(manifest)
		if err != nil {
			return fmt.Errorf("[data.path] %s", err)
		}
	case manifest.Data.Reader != types.Reader{}:
		err := validateReaderSignature(manifest)
		if err != nil {
			return fmt.Errorf("[data.reader] %s", err)
		}
	case manifest.Data.Raw != nil:
		err := manifest.CertificateChain[0].CheckSignature(manifest.SigningAlgorithm, *manifest.Data.Raw, *manifest.Signature)
		if err != nil {
			return fmt.Errorf("[data.raw] %s", err)
		}
	default:
		return errors.New("data not present within manifest")
	}

	err = validateCertificateChain(tc, manifest)
	if err != nil {
		return fmt.Errorf("[certificate chain] %s", err)
	}
	return nil
}

func validateCertificateChain(tc types.TrustChain, manifest types.Manifest) error {
	// Validate Entire Certificate Chain Does Not Break
	for i := range manifest.CertificateChain[:len(manifest.CertificateChain)-1] {
		err := manifest.CertificateChain[i].CheckSignatureFrom(manifest.CertificateChain[i+1])
		if err != nil {
			return fmt.Errorf("certificate chain invalid: %s", err)
		}
	}

	if manifest.CertificateChain[0].Subject.CommonName != tc.CommonName {
		return fmt.Errorf("invalid common name (cn) from code signing certificate")
	}

	validSubjectAlternativeName := false
	if len(manifest.CertificateChain[0].DNSNames) > 0 {
		for _, san := range manifest.CertificateChain[0].DNSNames {
			if san == tc.CommonName {
				validSubjectAlternativeName = true
			}
		}
	}

	if !validSubjectAlternativeName {
		return fmt.Errorf("invalid subject alternative name (san) from code signing certificate")
	}

	rootCertificatePool, err := generateCertificatePool(tc)
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		Roots:     rootCertificatePool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	switch len(manifest.CertificateChain) {
	// Single Root CA
	case 1:
		_, err = manifest.CertificateChain[0].Verify(opts)
		if err != nil {
			return fmt.Errorf("error validating code signing certificate validity: %w", err)
		}
	// Subordinate CA Validates Against AWS Intermediate CA Based on x509.VerifyOptions
	default:
		_, err = manifest.CertificateChain[1].Verify(opts)
		if err != nil {
			return fmt.Errorf("error validating code signing certificate validity: %w", err)
		}
	}
	return nil
}

func verifySignature(manifest types.Manifest) error {
	algorithm, exist := types.SignatureAlgorithm[manifest.SigningAlgorithm]
	if !exist {
		return fmt.Errorf("invalid signing algorithm: %s", manifest.SigningAlgorithm)
	}
	_, cryptoAlgorithm := algorithm()

	switch publicKey := manifest.CertificateChain[0].PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(publicKey, cryptoAlgorithm, *manifest.Hash, *manifest.Signature)
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(publicKey, *manifest.Hash, *manifest.Signature) {
			return nil
		}
		return errors.New("ecdsa signature verification failed")
	default:
		return errors.New("unsupported public key type")
	}
}

// Signature Validation for Large Files Passing in Filepath
func validateStreamedSignature(manifest types.Manifest) error {
	algorithm, exist := types.SignatureAlgorithm[manifest.SigningAlgorithm]
	if !exist {
		return fmt.Errorf("invalid signing algorithm: %s", manifest.SigningAlgorithm)
	}
	hashedAlgorithm, _ := algorithm()

	file, err := os.Open(manifest.Data.Path.File)
	if err != nil {
		return fmt.Errorf("error opening file: %s", err)
	}
	defer file.Close()

	if manifest.Data.Reader.Buffer > 0 {
		_buffer = manifest.Data.Reader.Buffer
	}

	buffer := make([]byte, _buffer)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading file: %s", err)
		}
		if n == 0 {
			break
		}
		hashedAlgorithm.Write(buffer[:n])
	}

	hashedArtifact := hashedAlgorithm.Sum(nil)
	manifest.Hash = &hashedArtifact

	err = verifySignature(manifest)
	if err != nil {
		return fmt.Errorf("signature verification failed: %s", err)
	}
	return nil
}

// Signature Validation for Large Files Passing in io.Reader
func validateReaderSignature(manifest types.Manifest) error {
	algorithm, exist := types.SignatureAlgorithm[manifest.SigningAlgorithm]
	if !exist {
		return fmt.Errorf("invalid signing algorithm: %s", manifest.SigningAlgorithm)
	}
	hashedAlgorithm, _ := algorithm()

	if manifest.Data.Reader.Buffer > 0 {
		_buffer = manifest.Data.Reader.Buffer
	}

	buffer := make([]byte, _buffer)
	for {
		n, err := manifest.Data.Reader.Interface.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading file: %s", err)
		}
		if n == 0 {
			break
		}
		hashedAlgorithm.Write(buffer[:n])
	}

	hashedArtifact := hashedAlgorithm.Sum(nil)
	manifest.Hash = &hashedArtifact

	err := verifySignature(manifest)
	if err != nil {
		return fmt.Errorf("signature verification failed: %s", err)
	}
	return nil
}

func generateCertificatePool(tc types.TrustChain) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	for _, dir := range tc.CertificateAuthorityDirectory {
		files, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate authority directory %s", dir)
		}

		for _, certFile := range files {
			data, err := os.ReadFile(filepath.Join(dir, certFile.Name()))
			if err != nil {
				return nil, fmt.Errorf("invalid certificate file %s", filepath.Join(dir, certFile.Name()))
			}
			pemBlock, _ := pem.Decode(data)
			if pemBlock == nil {
				return nil, errors.New("invalid input file")
			}
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing x.509 certificate: %w", err)
			}
			certPool.AddCert(cert)
		}
	}

	for _, ca := range tc.CertificateAuthorityFiles {
		data, err := os.ReadFile(filepath.Clean(ca))
		if err != nil {
			return nil, fmt.Errorf("invalid certificate authority file %s", filepath.Clean(ca))
		}
		pemBlock, _ := pem.Decode(data)
		if pemBlock == nil {
			return nil, errors.New("invalid input file")
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, errors.New("error parsing x.509 certificate")
		}
		certPool.AddCert(cert)
	}
	return certPool, nil
}

func validateManifestParameters(manifest types.Manifest) error {
	if manifest.Signature == nil {
		return errors.New("signature not found")
	}

	if manifest.SigningAlgorithm == 0 {
		return errors.New("signing algorithm not found")
	}

	if len(manifest.CertificateChain) == 0 {
		return errors.New("certificate chain not found")
	}

	if (manifest.Data.Path == types.Path{} &&
		manifest.Data.Raw == nil &&
		manifest.Data.Reader == types.Reader{}) {
		return errors.New("data not found")
	}
	return nil
}
