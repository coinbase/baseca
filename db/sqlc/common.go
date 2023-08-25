package db

import "github.com/coinbase/baseca/internal/types"

type CertificateResponseData struct {
	Certificate                  string                    `json:"certificate"`
	IntermediateCertificateChain string                    `json:"intermediate_certificate_chain,omitempty"`
	RootCertificateChain         string                    `json:"root_certificate_chain,omitempty"`
	Metadata                     types.CertificateMetadata `json:"metadata"`
}

type DatabaseEndpoints struct {
	Writer Store
	Reader Store
}

type CachedServiceAccount struct {
	ServiceAccount Account        `json:"service_account"`
	AwsIid         AwsAttestation `json:"aws_iid"`
}

type CachedProvisionerAccount struct {
	ProvisionerAccount Provisioner    `json:"provisioner_account"`
	AwsIid             AwsAttestation `json:"aws_iid"`
}
