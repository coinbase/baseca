package accounts

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/attestor/aws_iid"
	"github.com/coinbase/baseca/internal/authentication"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	"github.com/coinbase/baseca/internal/validator"
	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) CreateServiceAccount(ctx context.Context, req *apiv1.CreateServiceAccountRequest) (*apiv1.CreateServiceAccountResponse, error) {
	var service *db.Account
	nodeAttestation := []string{}

	subject_alternative_names := validator.SanitizeInput(req.SubjectAlternativeNames)
	certificate_authorities := validator.SanitizeInput(req.CertificateAuthorities)

	err := s.validateCertificateParameters(req.CertificateAuthorities, req.Environment, int16(req.CertificateValidity), req.SubordinateCa)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, err.Error()), err)
	}

	// Validate Subject Alternate Name and Regular Expression
	err = s.validateSanInput(ctx, req.ServiceAccount, req.Environment, req.SubjectAlternativeNames, req.RegularExpression)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, err.Error()), err)
	}

	if _, ok := types.CertificateRequestExtension[req.ExtendedKey]; !ok {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid extended key"), fmt.Errorf("invalid key extension [%s]", req.ExtendedKey))
	}

	if ok := validator.ValidateEmail(req.Email); !ok {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid email"), fmt.Errorf("invalid email [%s]", req.Email))
	}

	if len(req.Team) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid team parameter"), fmt.Errorf("invalid team [%s]", req.Team))
	}

	client_id, err := uuid.NewRandom()
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	clientToken, err := authentication.GenerateClientToken(32)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	hashedClientToken, err := authentication.HashPassword(clientToken)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	payload, ok := ctx.Value(types.AuthorizationPayloadKey).(*authentication.Claims)
	if !ok {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), fmt.Errorf("service auth context missing"))
	}

	// Production Service Accounts Require Attestation
	if req.Environment == "production" {
		if err = validateNodeAttestation(req.NodeAttestation); err != nil {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, err.Error()), err)
		}
	}

	if req.NodeAttestation != nil {
		nodeAttestation = aws_iid.GetNodeAttestation(req.NodeAttestation)

		account_arg := db.CreateServiceAccountParams{
			ClientID:                    client_id,
			ApiToken:                    hashedClientToken,
			ServiceAccount:              req.ServiceAccount,
			Environment:                 req.Environment,
			NodeAttestation:             nodeAttestation,
			Team:                        req.Team,
			Email:                       req.Email,
			ValidSubjectAlternateName:   subject_alternative_names,
			ValidCertificateAuthorities: certificate_authorities,
			ExtendedKey:                 req.ExtendedKey,
			CertificateValidity:         int16(req.CertificateValidity),
			SubordinateCa:               req.SubordinateCa,
			CreatedBy:                   payload.Subject,
			CreatedAt:                   time.Now().UTC(),
		}

		if req.RegularExpression != nil {
			account_arg.RegularExpression = sql.NullString{String: *req.RegularExpression, Valid: len(*req.RegularExpression) != 0}
		}

		raw_message, err := validator.MapToNullRawMessage(req.NodeAttestation.AwsIid.InstanceTags)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
		}

		iid_arg := db.StoreInstanceIdentityDocumentParams{
			ClientID:        client_id,
			RoleArn:         sql.NullString{String: req.NodeAttestation.AwsIid.RoleArn, Valid: len(req.NodeAttestation.AwsIid.RoleArn) != 0},
			AssumeRole:      sql.NullString{String: req.NodeAttestation.AwsIid.AssumeRole, Valid: len(req.NodeAttestation.AwsIid.AssumeRole) != 0},
			Region:          sql.NullString{String: req.NodeAttestation.AwsIid.Region, Valid: len(req.NodeAttestation.AwsIid.Region) != 0},
			InstanceID:      sql.NullString{String: req.NodeAttestation.AwsIid.InstanceId, Valid: len(req.NodeAttestation.AwsIid.InstanceId) != 0},
			ImageID:         sql.NullString{String: req.NodeAttestation.AwsIid.ImageId, Valid: len(req.NodeAttestation.AwsIid.ImageId) != 0},
			SecurityGroupID: req.NodeAttestation.AwsIid.SecurityGroups,
			InstanceTags:    raw_message,
		}

		service, err = s.store.Writer.TxCreateServiceAccount(ctx, account_arg, iid_arg)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "error creating account"), err)
		}
	} else {
		account_arg := db.CreateServiceAccountParams{
			ClientID:                    client_id,
			ApiToken:                    hashedClientToken,
			ServiceAccount:              req.ServiceAccount,
			Environment:                 req.Environment,
			NodeAttestation:             nodeAttestation,
			Team:                        req.Team,
			Email:                       req.Email,
			ValidSubjectAlternateName:   subject_alternative_names,
			ValidCertificateAuthorities: certificate_authorities,
			ExtendedKey:                 req.ExtendedKey,
			CertificateValidity:         int16(req.CertificateValidity),
			SubordinateCa:               req.SubordinateCa,
			CreatedBy:                   payload.Subject,
			CreatedAt:                   time.Now().UTC(),
		}

		if req.RegularExpression != nil {
			account_arg.RegularExpression = sql.NullString{String: *req.RegularExpression, Valid: len(*req.RegularExpression) != 0}
		}

		service, err = s.store.Writer.CreateServiceAccount(ctx, account_arg)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "error creating account"), err)
		}
	}

	account := apiv1.CreateServiceAccountResponse{
		ClientId:                service.ClientID.String(),
		ClientToken:             clientToken,
		ServiceAccount:          service.ServiceAccount,
		Environment:             service.Environment,
		NodeAttestation:         req.NodeAttestation,
		SubjectAlternativeNames: service.ValidSubjectAlternateName,
		ExtendedKey:             service.ExtendedKey,
		CertificateAuthorities:  service.ValidCertificateAuthorities,
		CertificateValidity:     int32(service.CertificateValidity),
		SubordinateCa:           service.SubordinateCa,
		Team:                    service.Team,
		Email:                   service.Email,
		CreatedAt:               timestamppb.New(service.CreatedAt),
		CreatedBy:               service.CreatedBy.String(),
	}

	if service.RegularExpression.Valid {
		account.RegularExpression = service.RegularExpression.String
	}

	return &account, nil
}
