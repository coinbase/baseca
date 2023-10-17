package acmpca

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/coinbase/baseca/internal/types"
)

type PrivateCaClientIface interface {
	IssueCertificate(ctx context.Context, params *acmpca.IssueCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error)
	GetCertificate(ctx context.Context, params *acmpca.GetCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.GetCertificateOutput, error)
	RevokeCertificate(ctx context.Context, params *acmpca.RevokeCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.RevokeCertificateOutput, error)
	GetCertificateAuthorityCertificate(ctx context.Context, params *acmpca.GetCertificateAuthorityCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.GetCertificateAuthorityCertificateOutput, error)
}

type PrivateCaClient struct {
	Client PrivateCaClientIface
	waiter *acmpca.CertificateIssuedWaiter
}

func NewPrivateCaClient(parameters types.CertificateParameters) (*PrivateCaClient, error) {
	cfg, _ := config.LoadDefaultConfig(context.TODO())
	stsclient := sts.NewFromConfig(cfg)

	if parameters.AssumeRole {
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsclient, parameters.RoleArn)
		cfg.Region = parameters.Region
	}

	client := acmpca.NewFromConfig(cfg)
	return &PrivateCaClient{
		Client: client,
	}, nil
}
