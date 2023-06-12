package accounts

import (
	"context"
	"database/sql"
	"fmt"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	"github.com/coinbase/baseca/internal/validator"
	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) ListServiceAccounts(ctx context.Context, req *apiv1.QueryParameter) (*apiv1.ServiceAccounts, error) {
	var accounts apiv1.ServiceAccounts

	if req.PageId <= 0 || req.PageSize <= 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid request parameters"), fmt.Errorf("invalid page_id or page_size"))
	}

	arg := db.ListServiceAccountsParams{
		Limit:  req.PageSize,
		Offset: (req.PageId - 1) * req.PageSize,
	}

	services, err := s.store.Reader.ListServiceAccounts(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	for _, service := range services {
		account, err := s.accountQuery(ctx, service)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
		}
		accounts.ServiceAccounts = append(accounts.ServiceAccounts, account)
	}

	return &accounts, nil
}

func (s *Service) GetServiceAccountUuid(ctx context.Context, req *apiv1.ServiceAccountId) (*apiv1.ServiceAccount, error) {
	id, err := uuid.Parse(req.Uuid)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid uuid parameter"), err)
	}

	service, err := s.store.Reader.GetServiceUUID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), fmt.Errorf("service account uuid %s does not exist", id))
		}
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	account, err := s.accountQuery(ctx, service)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return account, nil
}

func (s *Service) accountQuery(ctx context.Context, account *db.Account) (*apiv1.ServiceAccount, error) {
	var attestation types.NodeAttestation

	if validator.Contains(account.NodeAttestation, types.Attestation.AWS_IID) {
		iid, err := s.store.Reader.GetInstanceIdentityDocument(ctx, account.ClientID)
		if err != nil {
			return nil, err
		}

		instance_tag_map, err := validator.ConvertNullRawMessageToMap(iid.InstanceTags)
		if err != nil {
			return nil, err
		}

		// TODO: Update awsIid {} Response
		attestation = types.NodeAttestation{
			AWSInstanceIdentityDocument: types.AWSInstanceIdentityDocument{
				RoleArn:        iid.RoleArn.String,
				AssumeRole:     iid.AssumeRole.String,
				SecurityGroups: iid.SecurityGroupID,
				Region:         iid.Region.String,
				InstanceID:     iid.InstanceID.String,
				ImageID:        iid.ImageID.String,
				InstanceTags:   instance_tag_map,
			},
		}
	}

	return &apiv1.ServiceAccount{
		ClientId:                account.ClientID.String(),
		ServiceAccount:          account.ServiceAccount,
		Environment:             account.Environment,
		RegularExpression:       account.RegularExpression.String,
		SubjectAlternativeNames: account.ValidSubjectAlternateName,
		CertificateAuthorities:  account.ValidCertificateAuthorities,
		ExtendedKey:             account.ExtendedKey,
		CertificateValidity:     int32(account.CertificateValidity),
		Team:                    account.Team,
		Email:                   account.Email,
		CreatedAt:               timestamppb.New(account.CreatedAt),
		CreatedBy:               account.CreatedBy.String(),
		NodeAttestation: &apiv1.NodeAttestation{
			AwsIid: &apiv1.AWSInstanceIdentityDocument{
				RoleArn:        attestation.AWSInstanceIdentityDocument.RoleArn,
				AssumeRole:     attestation.AWSInstanceIdentityDocument.AssumeRole,
				SecurityGroups: attestation.AWSInstanceIdentityDocument.SecurityGroups,
				Region:         attestation.AWSInstanceIdentityDocument.Region,
				InstanceId:     attestation.AWSInstanceIdentityDocument.InstanceID,
				InstanceTags:   attestation.AWSInstanceIdentityDocument.InstanceTags,
			},
		},
	}, nil
}

func (s *Service) GetServiceAccountName(ctx context.Context, req *apiv1.ServiceAccountName) (*apiv1.ServiceAccounts, error) {
	var accounts apiv1.ServiceAccounts
	account_name := req.ServiceAccount

	if len(req.ServiceAccount) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid service_account parameter"), fmt.Errorf("invalid service_account parameter"))
	}

	service_accounts, err := s.store.Reader.GetServiceAccounts(ctx, account_name)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	for _, service_account := range service_accounts {
		account, err := s.accountQuery(ctx, service_account)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
		}
		accounts.ServiceAccounts = append(accounts.ServiceAccounts, account)
	}

	return &accounts, nil
}
