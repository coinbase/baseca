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
		CertificatePath:      certificateRequest.Output.Certificate,
		CertificateChainPath: certificateRequest.Output.CertificateChain})

	if err != nil {
		return nil, err
	}

	return signedCertificate, nil
}

func (c *client) ProvisionIssueCertificate(certificateRequest CertificateRequest, ca *apiv1.CertificateAuthorityParameter, service, environment, extendedKey string) (*apiv1.SignedCertificate, error) {
	signingRequest, err := GenerateCSR(certificateRequest)
	if err != nil {
		return nil, err
	}

	req := apiv1.OperationsSignRequest{
		CertificateSigningRequest: signingRequest.CSR.String(),
		CertificateAuthority:      ca,
		ServiceAccount:            service,
		Environment:               environment,
		ExtendedKey:               extendedKey,
	}

	signedCertificate, err := c.Certificate.OperationsSignCSR(context.Background(), &req)
	if err != nil {
		return nil, err
	}

	err = parseCertificateFormat(signedCertificate, SignedCertificate{
		CertificatePath:      certificateRequest.Output.Certificate,
		CertificateChainPath: certificateRequest.Output.CertificateChain})

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

	// Certificate Chain Path
	if len(parameter.CertificateChainPath) != 0 {
		certificate := []byte(certificate.CertificateChain)
		if err := os.WriteFile(parameter.CertificateChainPath, certificate, os.ModePerm); err != nil {
			return fmt.Errorf("error writing certificate chain to [%s]", parameter.CertificateChainPath)
		}
	}
	return nil
}
