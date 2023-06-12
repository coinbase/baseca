package types

type NodeAttestation struct {
	AWSInstanceIdentityDocument AWSInstanceIdentityDocument `json:"aws_iid"`
}

type AWSInstanceIdentityDocument struct {
	RoleArn        string            `json:"instance_profile_arn,omitempty"`
	AssumeRole     string            `json:"assume_role,omitempty"`
	SecurityGroups []string          `json:"security_groups,omitempty"`
	Region         string            `json:"region,omitempty"`
	InstanceID     string            `json:"instance_id,omitempty"`
	ImageID        string            `json:"image_id,omitempty"`
	InstanceTags   map[string]string `json:"instance_tags,omitempty"`
}

type Node struct {
	AWS_IID string
}

var Attestation = Node{
	AWS_IID: "AWS_IID",
}
