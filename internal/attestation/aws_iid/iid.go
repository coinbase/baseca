package aws_iid

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/allegro/bigcache/v3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/types"
	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
)

const (
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html (Other AWS Regions)
	aws_certificate_path = "internal/attestor/aws_iid/certificate/ec2.amazonaws.com.crt"
)

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

var (
	instanceFilters = []ec2types.Filter{
		{
			Name: aws.String("instance-state-name"),
			Values: []string{
				"pending",
				"running",
			},
		},
	}
)

func buildEC2Client(region string, roleARN string) (*ec2.Client, error) {
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, err
	}

	if isValidRoleArn(roleARN) {
		stsSvc := sts.NewFromConfig(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsSvc, roleARN)
	}

	svc := ec2.NewFromConfig(cfg)
	return svc, nil
}

func isValidRoleArn(arn string) bool {
	pattern := `^arn:aws:iam::[0-9]{12}:role\/[a-zA-Z0-9+=,.@_-]{1,64}$`
	re := regexp.MustCompile(pattern)
	return re.MatchString(arn)
}

func validateMetadataSignature(iid types.EC2InstanceMetadata) error {
	certificate, err := os.ReadFile(filepath.Clean(aws_certificate_path))
	if err != nil {
		return fmt.Errorf("error reading aws certificate for signature validation")
	}

	rsa_certificate_pem, _ := pem.Decode([]byte(certificate))
	rsa_certificate, _ := x509.ParseCertificate(rsa_certificate_pem.Bytes)
	signature, _ := base64.StdEncoding.DecodeString(string(iid.InstanceIdentitySignature))

	err = rsa_certificate.CheckSignature(x509.SHA256WithRSA, iid.InstanceIdentityDocument, signature)
	if err != nil {
		return fmt.Errorf("invalid aws_iid signature")
	}

	return nil
}

func GetInstanceIdentityDocument(ctx context.Context, db_reader db.Store, client_id uuid.UUID) (*db.AwsAttestation, error) {
	node_attestation, err := db_reader.GetInstanceIdentityDocument(ctx, client_id)
	if err != nil {
		return nil, fmt.Errorf("error retrieving aws_attestation from db, %s", err)
	}
	return node_attestation, nil
}

func AWSIidNodeAttestation(client_uuid uuid.UUID, header_metadata string, iid db.AwsAttestation, cache *bigcache.BigCache) error {
	var client *ec2.Client
	var instance ec2types.Instance
	var err error

	request_metadata_byte := []byte(header_metadata)
	instance_metadata := types.EC2InstanceMetadata{}
	instance_identity_document := InstanceIdentityDocument{}

	err = json.Unmarshal(request_metadata_byte, &instance_metadata)
	if err != nil {
		return fmt.Errorf("error unmarshal aws_instance metadata")
	}

	err = validateMetadataSignature(instance_metadata)
	if err != nil {
		return err
	}

	err = json.Unmarshal(instance_metadata.InstanceIdentityDocument, &instance_identity_document)
	if err != nil {
		return fmt.Errorf("error unmarshal aws_iid metadata")
	}

	// Query Instance Metadata in Cache
	hash := sha256.Sum256(instance_metadata.InstanceIdentityDocument)
	hash_key := hex.EncodeToString(hash[:])

	if value, cached := cache.Get(hash_key); cached != nil {
		client, err = buildEC2Client(instance_identity_document.Region, iid.AssumeRole.String)
		if err != nil {
			return fmt.Errorf("error building ec2 client, %s", err)
		}

		instancesDesc, err := client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
			InstanceIds: []string{instance_identity_document.InstanceId},
			Filters:     instanceFilters,
		})
		if err != nil {
			return fmt.Errorf("ec2 describe instances failed, %s", err)
		}

		instance, err = getEC2Instance(instancesDesc)
		if err != nil {
			return fmt.Errorf("error querying ec2 instance, %s", err)
		}

		// IAM Role Arn Attestation
		if iid.RoleArn.Valid {
			if *instance.IamInstanceProfile.Arn != iid.RoleArn.String {
				return fmt.Errorf("aws_iid role arn attestation error [client_id %s] [instance_identity_document %s]", client_uuid, instance_identity_document)
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
	} else {
		// SHA-256 Instance Identity Document [Key], Client ID [Value]. Multiple Instances Map to Single Client ID.
		err = json.Unmarshal(value, &iid)
		if err != nil {
			return fmt.Errorf("error unmarshal hashed iid in cached, %s", err)
		}
		attested_client_id := iid.ClientID
		if attested_client_id != client_uuid {
			return fmt.Errorf("request client id does not match attested node in cache")
		}
	}
	return nil
}

func getEC2Instance(instancesDesc *ec2.DescribeInstancesOutput) (ec2types.Instance, error) {
	if len(instancesDesc.Reservations) < 1 {
		return ec2types.Instance{}, status.Error(codes.Internal, "failed to query AWS via describe-instances: returned no reservations")
	}

	if len(instancesDesc.Reservations[0].Instances) < 1 {
		return ec2types.Instance{}, status.Error(codes.Internal, "failed to query AWS via describe-instances: returned no instances")
	}

	return instancesDesc.Reservations[0].Instances[0], nil
}

func GetNodeAttestation(node_attestation *apiv1.NodeAttestation) []string {
	var valid_attestation []string
	var iid = node_attestation.AwsIid

	// AWS Node Attestation
	if iid != nil {
		attestation := iid.RoleArn == "" && iid.AssumeRole == "" && len(iid.SecurityGroups) == 0 &&
			iid.Region == "" && iid.InstanceId == "" && iid.ImageId == "" &&
			len(iid.InstanceTags) == 0

		if !attestation {
			valid_attestation = append(valid_attestation, types.Attestation.AWS_IID)
		}
	}

	return valid_attestation
}
