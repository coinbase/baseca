package middleware

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	db "github.com/coinbase/baseca/db/sqlc"
	"github.com/coinbase/baseca/internal/attestation/aws_iid"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/internal/types"
	"github.com/google/uuid"
)

func (m *Middleware) searchServiceAccountMetadata(ctx context.Context, client_uuid uuid.UUID) (*db.ServiceAccountAttestation, error) {
	var service_account *db.Account
	var cached_service_account db.ServiceAccountAttestation
	var instance_identity_document *types.EC2NodeAttestation
	var err error

	db_reader := m.store.Reader
	uuid := client_uuid.String()
	if value, cached := m.cache.Get(uuid); cached == nil {
		err = json.Unmarshal(value, &cached_service_account)
		if err != nil {
			return &cached_service_account, fmt.Errorf("error unmarshal cached service account account, %s", err)
		}
	} else {
		service_account, err = db_reader.GetServiceUUID(ctx, client_uuid)
		if err != nil {
			return &cached_service_account, fmt.Errorf("service authentication failed: %s", err)
		}
		cached_service_account.ServiceAccount = *service_account

		for _, node_attestation := range service_account.NodeAttestation {
			switch node_attestation {
			case types.AWS_IID.String():
				instance_identity_document, err = aws_iid.GetInstanceIdentityDocument(ctx, db_reader, client_uuid)
				if err != nil {
					return &cached_service_account, fmt.Errorf("aws_iid node attestation failed: %s", err)
				}

				instance_tags, err := validator.MapToNullRawMessage(instance_identity_document.InstanceTags)
				if err != nil {
					return &cached_service_account, fmt.Errorf("error marshalling instance tags, %s", err)
				}
				cached_service_account.AwsIid = db.AwsAttestation{
					ClientID:        instance_identity_document.ClientID,
					RoleArn:         sql.NullString{String: instance_identity_document.RoleArn, Valid: len(instance_identity_document.RoleArn) != 0},
					AssumeRole:      sql.NullString{String: instance_identity_document.AssumeRole, Valid: len(instance_identity_document.AssumeRole) != 0},
					SecurityGroupID: instance_identity_document.SecurityGroups,
					Region:          sql.NullString{String: instance_identity_document.Region, Valid: len(instance_identity_document.Region) != 0},
					InstanceID:      sql.NullString{String: instance_identity_document.InstanceID, Valid: len(instance_identity_document.InstanceID) != 0},
					ImageID:         sql.NullString{String: instance_identity_document.ImageID, Valid: len(instance_identity_document.ImageID) != 0},
					InstanceTags:    instance_tags,
				}
			}
		}

		data, err := json.Marshal(cached_service_account)
		if err != nil {
			return &cached_service_account, fmt.Errorf("error marshalling cached_service_account, %s", err)
		}
		err = m.cache.Set(uuid, data)
		if err != nil {
			return &cached_service_account, fmt.Errorf("error setting middleware cache, %s", err)
		}
	}
	return &cached_service_account, nil
}

func (m *Middleware) serachProvisionerAccountAttestation(ctx context.Context, client_uuid uuid.UUID) (*db.ProvisionerAccountAttestation, error) {
	var provisioner_account *db.Provisioner
	var instance_identity_document *types.EC2NodeAttestation
	var cached_provisioner_account db.ProvisionerAccountAttestation
	var err error

	db_reader := m.store.Reader
	uuid := client_uuid.String()
	if value, cached := m.cache.Get(uuid); cached == nil {
		err = json.Unmarshal(value, &cached_provisioner_account)
		if err != nil {
			return &cached_provisioner_account, fmt.Errorf("error unmarshal cached service account account, %s", err)
		}
	} else {
		provisioner_account, err = db_reader.GetProvisionerUUID(ctx, client_uuid)
		if err != nil {
			return &cached_provisioner_account, fmt.Errorf("service authentication failed: %s", err)
		}
		cached_provisioner_account.ProvisionerAccount = *provisioner_account

		for _, node_attestation := range provisioner_account.NodeAttestation {
			switch node_attestation {
			case types.AWS_IID.String():
				instance_identity_document, err = aws_iid.GetInstanceIdentityDocument(ctx, db_reader, client_uuid)
				if err != nil {
					return &cached_provisioner_account, fmt.Errorf("aws_iid node attestation failed: %s", err)
				}

				instance_tags, err := validator.MapToNullRawMessage(instance_identity_document.InstanceTags)
				if err != nil {
					return &cached_provisioner_account, fmt.Errorf("error marshalling instance tags, %s", err)
				}
				cached_provisioner_account.AwsIid = db.AwsAttestation{
					ClientID:        instance_identity_document.ClientID,
					RoleArn:         sql.NullString{String: instance_identity_document.RoleArn, Valid: len(instance_identity_document.RoleArn) != 0},
					AssumeRole:      sql.NullString{String: instance_identity_document.AssumeRole, Valid: len(instance_identity_document.AssumeRole) != 0},
					SecurityGroupID: instance_identity_document.SecurityGroups,
					Region:          sql.NullString{String: instance_identity_document.Region, Valid: len(instance_identity_document.Region) != 0},
					InstanceID:      sql.NullString{String: instance_identity_document.InstanceID, Valid: len(instance_identity_document.InstanceID) != 0},
					ImageID:         sql.NullString{String: instance_identity_document.ImageID, Valid: len(instance_identity_document.ImageID) != 0},
					InstanceTags:    instance_tags,
				}
			}
		}

		data, err := json.Marshal(cached_provisioner_account)
		if err != nil {
			return &cached_provisioner_account, fmt.Errorf("error marshalling cached_service_account, %s", err)
		}
		err = m.cache.Set(uuid, data)
		if err != nil {
			return &cached_provisioner_account, fmt.Errorf("error setting middleware cache, %s", err)
		}
	}
	return &cached_provisioner_account, nil
}
