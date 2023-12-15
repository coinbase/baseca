package aws_iid

import (
	"context"
	"fmt"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/internal/types"
	"github.com/google/uuid"
)

func GetInstanceIdentityDocument(ctx context.Context, db_reader db.Store, client_id uuid.UUID) (*types.EC2NodeAttestation, error) {
	node_attestation, err := db_reader.GetInstanceIdentityDocument(ctx, client_id)
	if err != nil {
		return nil, fmt.Errorf("error retrieving aws_attestation from db, %s", err)
	}

	instance_tag_map, err := validator.ConvertNullRawMessageToMap(node_attestation.InstanceTags)
	if err != nil {
		return nil, err
	}

	return &types.EC2NodeAttestation{
		ClientID:       node_attestation.ClientID,
		RoleArn:        node_attestation.RoleArn.String,
		AssumeRole:     node_attestation.AssumeRole.String,
		SecurityGroups: node_attestation.SecurityGroupID,
		Region:         node_attestation.Region.String,
		InstanceID:     node_attestation.InstanceID.String,
		ImageID:        node_attestation.ImageID.String,
		InstanceTags:   instance_tag_map,
	}, nil
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
			valid_attestation = append(valid_attestation, types.AWS_IID.String())
		}
	}

	return valid_attestation
}
