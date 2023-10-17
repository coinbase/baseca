package db

import (
	"context"
	"database/sql"

	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/internal/types"
)

func (store *SQLStore) TxUpdateServiceAccount(ctx context.Context, arg Account, attestation types.NodeAttestation) (*Account, error) {
	var serviceAccountResponse *Account
	// TODO: Input Validation for Service Account

	updateServiceAccountInput := UpdateServiceAccountParams{
		ClientID:                    arg.ClientID,
		Environment:                 arg.Environment,
		Team:                        arg.Team,
		Email:                       arg.Email,
		RegularExpression:           arg.RegularExpression,
		ValidSubjectAlternateName:   arg.ValidCertificateAuthorities,
		ValidCertificateAuthorities: arg.ValidCertificateAuthorities,
		ExtendedKey:                 arg.ExtendedKey,
		CertificateValidity:         arg.CertificateValidity,
		SubordinateCa:               arg.SubordinateCa,
		NodeAttestation:             arg.NodeAttestation,
	}

	raw_message, err := validator.MapToNullRawMessage(attestation.AWSInstanceIdentityDocument.InstanceTags)
	if err != nil {
		return nil, err
	}

	iid := StoreInstanceIdentityDocumentParams{
		ClientID:        arg.ClientID,
		RoleArn:         sql.NullString{String: attestation.AWSInstanceIdentityDocument.RoleArn, Valid: len(attestation.AWSInstanceIdentityDocument.RoleArn) != 0},
		AssumeRole:      sql.NullString{String: attestation.AWSInstanceIdentityDocument.AssumeRole, Valid: len(attestation.AWSInstanceIdentityDocument.AssumeRole) != 0},
		SecurityGroupID: attestation.AWSInstanceIdentityDocument.SecurityGroups,
		Region:          sql.NullString{String: attestation.AWSInstanceIdentityDocument.Region, Valid: len(attestation.AWSInstanceIdentityDocument.Region) != 0},
		InstanceID:      sql.NullString{String: attestation.AWSInstanceIdentityDocument.InstanceID, Valid: len(attestation.AWSInstanceIdentityDocument.InstanceID) != 0},
		ImageID:         sql.NullString{String: attestation.AWSInstanceIdentityDocument.ImageID, Valid: len(attestation.AWSInstanceIdentityDocument.ImageID) != 0},
		InstanceTags:    raw_message,
	}

	err = store.execTx(ctx, func(q *Queries) error {
		var err error

		serviceAccountResponse, err = store.UpdateServiceAccount(ctx, updateServiceAccountInput)
		if err != nil {
			return err
		}

		for _, node_attestation := range arg.NodeAttestation {
			switch node_attestation {
			case types.Attestation.AWS_IID:
				// Add to AWS_IID Database
				_, err = store.StoreInstanceIdentityDocument(ctx, iid)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	return serviceAccountResponse, err
}
