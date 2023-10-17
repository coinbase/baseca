package acmpca

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

func (c *PrivateCaClient) RevokeCertificate(certificate_authority_arn string, serial_number string, revocation_reason string) (*acmpca.RevokeCertificateOutput, error) {
	revokeCertificateInput := &acmpca.RevokeCertificateInput{
		CertificateAuthorityArn: aws.String(certificate_authority_arn),
		CertificateSerial:       aws.String(serial_number),
		RevocationReason:        types.RevocationReason(revocation_reason),
	}
	return c.Client.RevokeCertificate(context.Background(), revokeCertificateInput)
}
