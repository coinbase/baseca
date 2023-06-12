package certificate

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/authentication"
	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/lib/crypto"
	"github.com/coinbase/baseca/internal/lib/util"
	"github.com/coinbase/baseca/internal/types"
	"github.com/coinbase/baseca/internal/validator"
)

const (
	_lockfile_duration = 30 * time.Second
)

func createServiceDirectory(serviceId string) error {
	directoryPath := filepath.Join(types.SubordinatePath, serviceId)

	if _, err := os.Stat(directoryPath); os.IsNotExist(err) {
		err := os.MkdirAll(directoryPath, os.ModePerm)
		if err != nil {
			return fmt.Errorf("error creating service directory [%s], %s", serviceId, err)
		}
	}
	return nil
}

func checkLockfile(serviceId string) error {
	lockfilePath := fmt.Sprintf("%s/%s/%s.lock", types.SubordinatePath, serviceId, serviceId)

	// Clean Stuck Lockfile
	if _, err := os.OpenFile(filepath.Clean(lockfilePath), os.O_RDONLY, 0400); err == nil {
		lockfile_stats, _ := os.Stat(lockfilePath)
		lockfile_creation := lockfile_stats.ModTime().UTC()
		if lockfile_creation.Add(_lockfile_duration).UTC().Before(time.Now().UTC()) {
			err = os.Remove(filepath.Clean(lockfilePath))
			if err != nil {
				return fmt.Errorf("error during lockfile creation %s", err)
			}
		}
	}

	err := util.LockfileBackoff(lockfilePath)
	if err != nil {
		return fmt.Errorf("error during lockfile backoff %s", err)
	}
	return nil
}

// Check if Subordinate Certificate Exists for Service
func loadSubordinateCaParameters(service string, auth *authentication.ServicePayload) (*types.CertificateAuthority, error) {
	x509_metadata, err := crypto.GetSubordinateCaParameters(service)
	if err != nil {
		return nil, err
	}

	if !validateSubordinateExpiration(auth.CertificateValidity, x509_metadata) {
		return nil, errors.New("certificate expiration exceeds subordinate ca expiration")
	}

	certificate_path, key_path, err := crypto.GetSubordinateCaPath(service)
	if err != nil {
		return nil, err
	}

	// Validate Non-Mismatch Between Private Key and Certificate
	_, err = tls.LoadX509KeyPair(*certificate_path, *key_path)
	if err != nil {
		return nil, err
	}
	return x509_metadata, nil
}

func validateSubordinateExpiration(certificate_validity int16, x509_metadata *types.CertificateAuthority) bool {
	certificate_expiration := x509_metadata.Certificate.NotAfter
	// Subordinate CA Expires Before End-Entity Certificate (Requires Re-Issuance of Subordinate)
	return !certificate_expiration.Before(time.Now().UTC().AddDate(0, 0, int(certificate_validity)).UTC())
}

func (c *Certificate) validateCsrParameters(parameters *apiv1.OperationsSignRequest) error {
	csrBlock, _ := pem.Decode([]byte(parameters.CertificateSigningRequest))
	if csrBlock == nil {
		return fmt.Errorf("certificate signing request (csr) could not be decoded")
	}

	request, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("certificate signing request (csr) invalid format")
	}

	dns := request.DNSNames
	for _, domain := range dns {
		if !validator.IsValidateDomain(domain) {
			return fmt.Errorf("%s is not a supported domain", domain)
		}
	}

	expirationDate := time.Now().UTC().AddDate(0, 0, int(parameters.CertificateAuthority.Validity)).UTC()
	if expirationDate.Before(time.Now().UTC().Add(time.Minute).UTC()) {
		return fmt.Errorf("certificate expiration before current time utc")
	}
	return nil
}

func convertX509toString(certificate []byte) (*bytes.Buffer, error) {
	buffer := new(bytes.Buffer)
	err := pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return nil, fmt.Errorf("error encoding x509 certificate: %s", err)
	}
	return buffer, nil
}

func ValidateSubordinateParameters(parameter config.SubordinateCertificateAuthority) error {
	switch parameter.KeyAlgorithm {
	case "RSA":
		if _, ok := types.ValidAlgorithms[parameter.KeyAlgorithm].KeySize[parameter.KeySize]; !ok {
			return fmt.Errorf("invalid rsa key size: %d", parameter.KeySize)
		}
		if _, ok := types.ValidAlgorithms[parameter.KeyAlgorithm].Signature[parameter.SigningAlgorithm]; !ok {
			return fmt.Errorf("invalid rsa signing algorithm: %s", parameter.SigningAlgorithm)
		}
	case "ECDSA":
		if _, ok := types.ValidAlgorithms[parameter.KeyAlgorithm].KeySize[parameter.KeySize]; !ok {
			return fmt.Errorf("invalid ecdsa key size: %d", parameter.KeySize)
		}
		if _, ok := types.ValidAlgorithms[parameter.KeyAlgorithm].Signature[parameter.SigningAlgorithm]; !ok {
			return fmt.Errorf("invalid ecdsa signing algorithm: %s", parameter.SigningAlgorithm)
		}
	default:
		return fmt.Errorf("public key algorithm not supported: %s", parameter.KeyAlgorithm)
	}
	return nil
}
