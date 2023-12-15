package aws_iid

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coinbase/baseca/pkg/attestor/aws_iid"
)

func validateMetadataSignature(iid aws_iid.EC2InstanceMetadata) error {
	certificate, err := os.ReadFile(filepath.Clean(aws_certificate_path))
	if err != nil {
		return fmt.Errorf("error reading aws certificate for signature validation")
	}

	rsa_certificate_pem, _ := pem.Decode([]byte(certificate))
	rsa_certificate, _ := x509.ParseCertificate(rsa_certificate_pem.Bytes)
	signature, _ := base64.StdEncoding.DecodeString(string(iid.InstanceIdentitySignature))

	err = rsa_certificate.CheckSignature(x509.SHA256WithRSA, iid.InstanceIdentityDocument, signature)
	if err != nil {
		return fmt.Errorf("invalid aws_iid signature")
	}

	return nil
}
