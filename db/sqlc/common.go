package db

type DatabaseEndpoints struct {
	Writer Store
	Reader Store
}

type ServiceAccountAttestation struct {
	ServiceAccount Account        `json:"service_account"`
	AwsIid         AwsAttestation `json:"aws_iid"`
}

type ProvisionerAccountAttestation struct {
	ProvisionerAccount Provisioner    `json:"provisioner_account"`
	AwsIid             AwsAttestation `json:"aws_iid"`
}
