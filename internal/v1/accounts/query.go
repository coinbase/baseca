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
		account, err := s.transformServiceAccount(ctx, service)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
		}
		accounts.ServiceAccounts = append(accounts.ServiceAccounts, account)
	}

	return &accounts, nil
}

func (s *Service) ListProvisionerAccounts(ctx context.Context, req *apiv1.QueryParameter) (*apiv1.ProvisionerAccounts, error) {
	var accounts apiv1.ProvisionerAccounts

	if req.PageId <= 0 || req.PageSize <= 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid request parameters"), fmt.Errorf("invalid page_id or page_size"))
	}

	arg := db.ListProvisionerAccountsParams{
		Limit:  req.PageSize,
		Offset: (req.PageId - 1) * req.PageSize,
	}

	provisioners, err := s.store.Reader.ListProvisionerAccounts(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	for _, provisioner := range provisioners {
		account, err := s.transformProvisionerAccount(ctx, provisioner)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
		}
		accounts.ProvisionerAccounts = append(accounts.ProvisionerAccounts, account)
	}
	return &accounts, nil
}

func (s *Service) GetServiceAccount(ctx context.Context, req *apiv1.AccountId) (*apiv1.ServiceAccount, error) {
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

	account, err := s.transformServiceAccount(ctx, service)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return account, nil
}

func (s *Service) GetProvisionerAccount(ctx context.Context, req *apiv1.AccountId) (*apiv1.ProvisionerAccount, error) {
	id, err := uuid.Parse(req.Uuid)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid uuid parameter"), err)
	}

	provisioner, err := s.store.Reader.GetProvisionerUUID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), fmt.Errorf("provisioner account uuid %s does not exist", id))
		}
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	account, err := s.transformProvisionerAccount(ctx, provisioner)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return account, nil
}

func (s *Service) transformServiceAccount(ctx context.Context, account *db.Account) (*apiv1.ServiceAccount, error) {
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
		SubordinateCa:           account.SubordinateCa,
		Provisioned:             account.Provisioned,
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

func (s *Service) transformProvisionerAccount(ctx context.Context, account *db.Provisioner) (*apiv1.ProvisionerAccount, error) {
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

	return &apiv1.ProvisionerAccount{
		ClientId:                account.ClientID.String(),
		ProvisionerAccount:      account.ProvisionerAccount,
		Environments:            account.Environments,
		RegularExpression:       account.RegularExpression.String,
		SubjectAlternativeNames: account.ValidSubjectAlternateNames,
		ExtendedKeys:            account.ExtendedKeys,
		MaxCertificateValidity:  uint32(account.MaxCertificateValidity),
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

func (s *Service) GetServiceAccountMetadata(ctx context.Context, req *apiv1.GetServiceAccountMetadataRequest) (*apiv1.ServiceAccounts, error) {
	var accounts apiv1.ServiceAccounts
	var serviceAccount, environment, extendedKey string

	if len(req.ServiceAccount) == 0 && len(req.Environment) == 0 && len(req.ExtendedKey) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid parameters"), fmt.Errorf("invalid parameters nil or empty"))
	}

	if len(req.ServiceAccount) == 0 {
		serviceAccount = "%"
	} else {
		serviceAccount = req.ServiceAccount
	}

	if len(req.Environment) == 0 {
		environment = "%"
	} else {
		if !validator.ValidateInput(req.Environment) {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid parameters"), fmt.Errorf("invalid environment: %s", req.ServiceAccount))
		}
		environment = req.Environment
	}

	if len(req.ExtendedKey) == 0 {
		extendedKey = "%"
	} else {
		if !validator.ValidateInput(req.ExtendedKey) {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid parameters"), fmt.Errorf("invalid extended key: %s", req.ExtendedKey))
		}
		extendedKey = req.ExtendedKey
	}

	arg := db.GetServiceAccountByMetadataParams{
		ServiceAccount: serviceAccount,
		Environment:    environment,
		ExtendedKey:    extendedKey,
	}

	services, err := s.store.Reader.GetServiceAccountByMetadata(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	for _, service := range services {
		account, err := s.transformServiceAccount(ctx, service)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
		}
		accounts.ServiceAccounts = append(accounts.ServiceAccounts, account)
	}

	return &accounts, nil
}
