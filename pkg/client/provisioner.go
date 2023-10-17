package baseca

import (
	"context"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/pkg/types"
)

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

	err = parseCertificateFormat(signedCertificate, types.SignedCertificate{
		CertificatePath:                  certificateRequest.Output.Certificate,
		IntermediateCertificateChainPath: certificateRequest.Output.IntermediateCertificateChain,
		RootCertificateChainPath:         certificateRequest.Output.RootCertificateChain,
	})

	if err != nil {
		return nil, err
	}

	return signedCertificate, nil
}

func (c *client) ProvisionServiceAccount(req *apiv1.ProvisionServiceAccountRequest) (*apiv1.ProvisionServiceAccountResponse, error) {
	return c.Service.ProvisionServiceAccount(context.Background(), req)
}

func (c *client) GetServiceAccountByMetadata(req *apiv1.GetServiceAccountMetadataRequest) (*apiv1.ServiceAccounts, error) {
	return c.Service.GetServiceAccountMetadata(context.Background(), req)
}
