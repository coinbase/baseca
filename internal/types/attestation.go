package types

import (
	"github.com/coinbase/baseca/pkg/attestor/aws_iid"
	"github.com/google/uuid"
)

type Attestation uint

const (
	AWS_IID Attestation = iota
)

func (a Attestation) String() string {
	return [...]string{
		"AWS_IID"}[a]
}

type NodeAttestation struct {
	EC2NodeAttestation EC2NodeAttestation `json:"aws_iid"`
}

// Node Attestation Configured in Database
type EC2NodeAttestation struct {
	ClientID       uuid.UUID         `json:"client_id"`
	RoleArn        string            `json:"instance_profile_arn,omitempty"`
	AssumeRole     string            `json:"assume_role,omitempty"`
	SecurityGroups []string          `json:"security_groups,omitempty"`
	Region         string            `json:"region,omitempty"`
	InstanceID     string            `json:"instance_id,omitempty"`
	ImageID        string            `json:"image_id,omitempty"`
	InstanceTags   map[string]string `json:"instance_tags,omitempty"`
}

type NodeIIDAttestation struct {
	Uuid                uuid.UUID
	EC2InstanceMetadata aws_iid.EC2InstanceMetadata
	Attestation         EC2NodeAttestation
}

type InstanceIdentityDocument struct {
	AccountId        string `json:"accountId"`
	Architecture     string `json:"architecture"`
	AvailabilityZone string `json:"availabilityZone"`
	ImageId          string `json:"imageId"`
	InstanceId       string `json:"instanceId"`
	InstanceType     string `json:"instanceType"`
	PrivateIp        string `json:"privateIp"`
	Region           string `json:"region"`
	Version          string `json:"version"`
}
