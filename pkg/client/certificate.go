package baseca

import (
	"context"
	"fmt"
	"os"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
)

func (c *client) IssueCertificate(certificateRequest CertificateRequest) (*apiv1.SignedCertificate, error) {
	signingRequest, err := GenerateCSR(certificateRequest)
	if err != nil {
		return nil, err
	}

	req := apiv1.CertificateSigningRequest{
		CertificateSigningRequest: signingRequest.CSR.String(),
	}

	signedCertificate, err := c.Certificate.SignCSR(context.Background(), &req)
	if err != nil {
		return nil, err
	}

	err = parseCertificateFormat(signedCertificate, SignedCertificate{
		CertificatePath:                  certificateRequest.Output.Certificate,
		IntermediateCertificateChainPath: certificateRequest.Output.IntermediateCertificateChain,
		RootCertificateChainPath:         certificateRequest.Output.RootCertificateChain,
	})

	if err != nil {
		return nil, err
	}

	return signedCertificate, nil
}

func parseCertificateFormat(certificate *apiv1.SignedCertificate, parameter SignedCertificate) error {
	// Leaf Certificate Path
	if len(parameter.CertificatePath) != 0 {
		certificate := []byte(certificate.Certificate)
		if err := os.WriteFile(parameter.CertificatePath, certificate, os.ModePerm); err != nil {
			return fmt.Errorf("error writing certificate to [%s]", parameter.CertificatePath)
		}
	}

	// Intermediate Certificate Chain Path
	if len(parameter.IntermediateCertificateChainPath) != 0 {
		certificate := []byte(certificate.IntermediateCertificateChain)
		if err := os.WriteFile(parameter.IntermediateCertificateChainPath, certificate, os.ModePerm); err != nil {
			return fmt.Errorf("error writing certificate to [%s]", parameter.IntermediateCertificateChainPath)
		}
	}

	// Root Certificate Chain Path
	if len(parameter.RootCertificateChainPath) != 0 {
		certificate := []byte(certificate.CertificateChain)
		if err := os.WriteFile(parameter.RootCertificateChainPath, certificate, os.ModePerm); err != nil {
			return fmt.Errorf("error writing certificate chain to [%s]", parameter.RootCertificateChainPath)
		}
	}
	return nil
}

func (c *client) QueryCertificateMetadata(req *apiv1.QueryCertificateMetadataRequest) (*apiv1.CertificatesParameter, error) {
	return c.Certificate.QueryCertificateMetadata(context.Background(), req)
}
