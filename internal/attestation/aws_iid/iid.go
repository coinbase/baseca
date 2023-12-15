package aws_iid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/allegro/bigcache/v3"
	"github.com/coinbase/baseca/internal/client/ec2"
	"github.com/coinbase/baseca/internal/types"
)

const (
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html (Other AWS Regions)
	aws_certificate_path = "config/aws/ec2.amazonaws.com.crt"
)

func AWSIidNodeAttestation(node types.NodeIIDAttestation, cache *bigcache.BigCache) error {
	err := validateMetadataSignature(node.EC2InstanceMetadata)
	if err != nil {
		return err
	}

	instance_identity_document := types.InstanceIdentityDocument{}
	err = json.Unmarshal(node.EC2InstanceMetadata.InstanceIdentityDocument, &instance_identity_document)
	if err != nil {
		return fmt.Errorf("error unmarshal aws_iid metadata")
	}

	err = searchIidCache(node, cache)
	if err != nil {
		return err
	}
	return nil
}

// Query Instance Metadata in Cache
func searchIidCache(node types.NodeIIDAttestation, cache *bigcache.BigCache) error {
	hash := sha256.Sum256(node.EC2InstanceMetadata.InstanceIdentityDocument)
	hash_key := hex.EncodeToString(hash[:])

	if value, err := cache.Get(hash_key); err != nil {
		// Cache Missed
		err := setIidCache(node, cache)
		if err != nil {
			return fmt.Errorf("error setting iid cache, %s", err)
		}
	} else {
		// SHA-256 Instance Identity Document [Key]
		// []byte Instance Identity Document [Value]
		document := types.InstanceIdentityDocument{}
		err := json.Unmarshal(value, &document)
		if err != nil {
			return fmt.Errorf("error unmarshal hashed iid in cached, %s", err)
		}
	}
	return nil
}

func setIidCache(node types.NodeIIDAttestation, cache *bigcache.BigCache) error {
	hash := sha256.Sum256(node.EC2InstanceMetadata.InstanceIdentityDocument)
	hash_key := hex.EncodeToString(hash[:])

	client, err := ec2.NewEC2Client(node.Attestation.Region, node.Attestation.AssumeRole)
	if err != nil {
		return fmt.Errorf("error building ec2 client, %s", err)
	}

	// Instance ID from EC2 IID
	iid := types.InstanceIdentityDocument{}
	err = json.Unmarshal(node.EC2InstanceMetadata.InstanceIdentityDocument, &iid)
	if err != nil {
		return fmt.Errorf("error unmarshal aws_iid metadata")
	}

	instance, err := ec2.QueryInstanceMetadata(context.Background(), client, []string{iid.InstanceId})
	if err != nil {
		return err
	}

	// IAM Role Arn Attestation
	if len(node.Attestation.RoleArn) > 0 {
		if *instance.IamInstanceProfile.Arn != node.Attestation.RoleArn {
			return fmt.Errorf("aws_iid role arn attestation error [client_id %s] %s", node.Uuid, string(node.EC2InstanceMetadata.InstanceIdentityDocument))
		}
	}

	data, err := json.Marshal(iid)
	if err != nil {
		return fmt.Errorf("error marshalling cached_service_account, %s", err)
	}

	err = cache.Set(hash_key, data)
	if err != nil {
		return fmt.Errorf("error setting hashed aws_iid in cache, %s", err)
	}

	return nil
}
