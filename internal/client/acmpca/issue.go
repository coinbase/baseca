package acm_pca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	pca_types "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/types"
)

const (
	_subordinateCACertificate_PathLen0_V1 = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
)

func (c *PrivateCaClient) IssueCertificateFromTemplate(parameters *apiv1.CertificateAuthorityParameter, csr []byte, template string) (*x509.Certificate, error) {
	idempotencyToken, err := generateIdempotencyToken()
	if err != nil {
		return nil, err
	}

	signingAlgorithm, ok := types.ValidSignatures[parameters.SignAlgorithm]
	if !ok {
		return nil, fmt.Errorf("signature algorithm %s invalid", parameters.SignAlgorithm)
	}

	certReq := acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(parameters.CaArn),
		Csr:                     csr,
		TemplateArn:             aws.String(template),
		SigningAlgorithm:        signingAlgorithm.PCA,
		Validity: &pca_types.Validity{
			Value: aws.Int64(int64(parameters.Validity)),
			Type:  pca_types.ValidityPeriodTypeDays,
		},
		IdempotencyToken: aws.String(*idempotencyToken),
	}

	certificateOutput, err := c.Client.IssueCertificate(context.Background(), &certReq)
	if err != nil {
		return nil, err
	}

	certificateInput := acmpca.GetCertificateInput{
		CertificateArn:          certificateOutput.CertificateArn,
		CertificateAuthorityArn: &parameters.CaArn,
	}

	certificate, err := c.waitUntilCertificateIssued(certificateInput)
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func (c *PrivateCaClient) IssueSubordinateCertificate(parameters types.CertificateParameters, algorithm string, csr []byte) (*x509.Certificate, error) {
	idempotencyToken, err := generateIdempotencyToken()
	if err != nil {
		return nil, err
	}

	signingAlgorithm, ok := types.ValidSignatures[algorithm]
	if !ok {
		return nil, fmt.Errorf("signature algorithm %s invalid", algorithm)
	}

	certReq := acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(parameters.CaArn),
		Csr:                     csr,
		TemplateArn:             aws.String(_subordinateCACertificate_PathLen0_V1),
		SigningAlgorithm:        signingAlgorithm.PCA,
		Validity: &pca_types.Validity{
			Value: aws.Int64(int64(parameters.Validity)),
			Type:  pca_types.ValidityPeriodTypeDays,
		},
		IdempotencyToken: aws.String(*idempotencyToken),
	}

	certificateOutput, err := c.Client.IssueCertificate(context.Background(), &certReq)
	if err != nil {
		return nil, err
	}

	certificateInput := acmpca.GetCertificateInput{
		CertificateArn:          certificateOutput.CertificateArn,
		CertificateAuthorityArn: &parameters.CaArn,
	}

	certificate, err := c.waitUntilCertificateIssued(certificateInput)
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func generateIdempotencyToken() (*string, error) {
	idempotency := make([]byte, 16)
	_, err := rand.Read(idempotency)
	if err != nil {
		return nil, fmt.Errorf("error generating idempotency token: %s", err)
	}

	encoded := hex.EncodeToString(idempotency)
	return &encoded, nil
}

// AWS Removed WaitUntilCertificateIssued(input *GetCertificateInput) in the v2 SDK
func (c *PrivateCaClient) waitUntilCertificateIssued(request acmpca.GetCertificateInput) (*x509.Certificate, error) {
	c.waiter = acmpca.NewCertificateIssuedWaiter(c.Client)
	err := c.waiter.Wait(context.Background(), &request, time.Duration(30*time.Second))
	if err != nil {
		return nil, err
	}
	certificatePem, err := c.Client.GetCertificate(context.Background(), &request)
	if err != nil {
		return nil, err
	}
	certPemBlock, _ := pem.Decode([]byte(*certificatePem.Certificate))
	if certPemBlock == nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certPemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return certificate, nil
}
