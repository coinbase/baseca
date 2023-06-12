package acm_pca

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

func (c *PrivateCaClient) GetSubordinateCAChain(certificate_authority_arn string) (*acmpca.GetCertificateAuthorityCertificateOutput, error) {
	input := acmpca.GetCertificateAuthorityCertificateInput{
		CertificateAuthorityArn: &certificate_authority_arn,
	}
	response, err := c.Client.GetCertificateAuthorityCertificate(context.Background(), &input)
	if err != nil {
		return nil, err
	}

	return response, nil
}
