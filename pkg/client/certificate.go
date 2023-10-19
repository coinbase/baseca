package baseca

import (
	"context"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/pkg/types"
	"github.com/coinbase/baseca/pkg/util"
)

func (c *Client) IssueCertificate(certificateRequest CertificateRequest) (*apiv1.SignedCertificate, error) {
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

	err = util.ParseCertificateFormat(signedCertificate, types.SignedCertificate{
		CertificatePath:                  certificateRequest.Output.Certificate,
		IntermediateCertificateChainPath: certificateRequest.Output.IntermediateCertificateChain,
		RootCertificateChainPath:         certificateRequest.Output.RootCertificateChain,
	})

	if err != nil {
		return nil, err
	}

	return signedCertificate, nil
}
