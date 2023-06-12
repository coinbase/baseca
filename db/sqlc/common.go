package db

import "github.com/coinbase/baseca/internal/types"

type CertificateResponseData struct {
	Certificate      string                    `json:"certificate"`
	CertificateChain string                    `json:"certificate_chain,omitempty"`
	Metadata         types.CertificateMetadata `json:"metadata"`
}

type DatabaseEndpoints struct {
	Writer Store
	Reader Store
}

type CachedServiceAccount struct {
	ServiceAccount Account        `json:"service_account"`
	AwsIid         AwsAttestation `json:"aws_iid"`
}
