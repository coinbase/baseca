package accounts

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/attestation/aws_iid"
	lib "github.com/coinbase/baseca/internal/lib/authentication"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) CreateProvisionerAccount(ctx context.Context, req *apiv1.CreateProvisionerAccountRequest) (*apiv1.CreateProvisionerAccountResponse, error) {
	var service *db.Provisioner
	nodeAttestation := []string{}

	subject_alternative_names := validator.SanitizeInput(req.SubjectAlternativeNames)

	err := s.validateSanInputProvisionerAccount(ctx, req.ProvisionerAccount, req.Environments, req.SubjectAlternativeNames, req.RegularExpression)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "provisioner subject alternative name (san) validation error"), fmt.Errorf("provisioner account subject alternative name validation error [%s]", err))
	}

	if req.MaxCertificateValidity <= 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid max_certificate_validity parameter"), fmt.Errorf("invalid max_certificate_validity parameter [%d]", req.MaxCertificateValidity))
	}

	if len(req.Environments) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid environments parameter"), fmt.Errorf("invalid environments parameter"))
	}

	for _, environment := range req.Environments {
		if _, ok := validator.CertificateAuthorityEnvironmentsString[environment]; !ok {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid certificate authority environment"), fmt.Errorf("invalid certificate authority environment [%s]", environment))
		}
	}

	if len(req.ExtendedKeys) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid extended keys parameter"), fmt.Errorf("invalid extended keys parameter"))
	}

	for _, extendedKey := range req.ExtendedKeys {
		if _, ok := types.CertificateRequestExtension[extendedKey]; !ok {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid extended key"), fmt.Errorf("invalid key extension [%s]", extendedKey))
		}
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

	clientToken, err := lib.GenerateClientToken(32)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	hashedClientToken, err := lib.HashPassword(clientToken)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	payload, ok := ctx.Value(types.UserAuthenticationContextKey).(*lib.Claims)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "service auth context missing")
	}

	if validator.Contains(req.Environments, types.Production.String()) || req.NodeAttestation != nil {
		if err = verifyNodeAttestationParameters(req.NodeAttestation); err != nil {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, err.Error()), err)
		}
	}

	if req.NodeAttestation != nil {
		nodeAttestation = aws_iid.GetNodeAttestation(req.NodeAttestation)

		account_arg := db.CreateProvisionerAccountParams{
			ClientID:                   client_id,
			ApiToken:                   hashedClientToken,
			ProvisionerAccount:         req.ProvisionerAccount,
			Environments:               req.Environments,
			NodeAttestation:            nodeAttestation,
			Team:                       req.Team,
			Email:                      req.Email,
			ValidSubjectAlternateNames: subject_alternative_names,
			ExtendedKeys:               req.ExtendedKeys,
			MaxCertificateValidity:     int16(req.MaxCertificateValidity),
			CreatedBy:                  payload.Subject,
			CreatedAt:                  time.Now().UTC(),
		}

		if len(req.RegularExpression) != 0 {
			account_arg.RegularExpression = sql.NullString{String: req.RegularExpression, Valid: len(req.RegularExpression) != 0}
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

		service, err = s.store.Writer.TxCreateProvisionerAccount(ctx, account_arg, iid_arg)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "error creating account"), err)
		}
	} else {
		account_arg := db.CreateProvisionerAccountParams{
			ClientID:                   client_id,
			ApiToken:                   hashedClientToken,
			ProvisionerAccount:         req.ProvisionerAccount,
			Environments:               req.Environments,
			NodeAttestation:            nodeAttestation,
			Team:                       req.Team,
			Email:                      req.Email,
			ValidSubjectAlternateNames: subject_alternative_names,
			ExtendedKeys:               req.ExtendedKeys,
			MaxCertificateValidity:     int16(req.MaxCertificateValidity),
			CreatedBy:                  payload.Subject,
			CreatedAt:                  time.Now().UTC(),
		}

		if len(req.RegularExpression) != 0 {
			account_arg.RegularExpression = sql.NullString{String: req.RegularExpression, Valid: len(req.RegularExpression) != 0}
		}

		service, err = s.store.Writer.CreateProvisionerAccount(ctx, account_arg)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "error creating account"), err)
		}
	}

	account := apiv1.CreateProvisionerAccountResponse{
		ClientId:                service.ClientID.String(),
		ClientToken:             clientToken,
		ProvisionerAccount:      service.ProvisionerAccount,
		Environments:            service.Environments,
		NodeAttestation:         req.NodeAttestation,
		SubjectAlternativeNames: service.ValidSubjectAlternateNames,
		ExtendedKeys:            service.ExtendedKeys,
		MaxCertificateValidity:  uint32(service.MaxCertificateValidity),
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

func (s *Service) DeleteProvisionAccount(ctx context.Context, req *apiv1.AccountId) (*emptypb.Empty, error) {
	client_id, err := uuid.Parse(req.Uuid)
	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.InvalidArgument, "invalid uuid format"), err)
	}

	err = s.store.Writer.TxDeleteProvisionerAccount(ctx, client_id)
	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) ProvisionServiceAccount(ctx context.Context, req *apiv1.ProvisionServiceAccountRequest) (*apiv1.ProvisionServiceAccountResponse, error) {
	var service *db.Account

	nodeAttestation := []string{}
	certAuth := []string{}

	subject_alternative_names := validator.SanitizeInput(req.SubjectAlternativeNames)
	certificate_authorities := validator.SanitizeInput(req.CertificateAuthorities)

	payload, ok := ctx.Value(types.ProvisionerAuthenticationContextKey).(*types.ProvisionerAccountPayload)
	if !ok {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "service auth context missing"), fmt.Errorf("service auth context missing"))
	}

	if !validator.Contains(payload.Environments, req.Environment) {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid environment"), fmt.Errorf("invalid environment [%s]", req.Environment))
	}

	err := s.validateSanInputServiceAccount(ctx, req.ServiceAccount, req.Environment, req.SubjectAlternativeNames, &req.RegularExpression)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "provisioner subject alternative name (san) validation error"), fmt.Errorf("provisioner subject alternative name validation error [%s]", err))
	}

	err = s.CheckSubordinateCaRegion(req.SubordinateCa, req.Region, req.Environment, req.CertificateAuthorities)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "subordinate ca does not support region"), fmt.Errorf("subordinate ca does not support region [%s] for service account [%s] %s", *req.Region, req.ServiceAccount, err))
	}

	regex, err := regexp.Compile(payload.RegularExpression)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	for _, reqSan := range req.SubjectAlternativeNames {
		if !validator.Contains(payload.ValidSubjectAlternateNames, reqSan) && !regex.Match([]byte(reqSan)) {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "internal server error"), fmt.Errorf("subject alternative name (san) %s exists in another provisioner account", reqSan))
		}
	}

	if len(certificate_authorities) == 0 {
		environment := req.Environment
		certificate_authorities := validator.CertificateAuthorityEnvironmentsString[environment]

		// Include Default Certificate Authorities
		for _, ca := range certificate_authorities {
			ca_metadata := s.acmConfig[ca]
			if ca_metadata.Default {
				// Add Default Certificate Authorities for Region
				if req.Region != nil && ca_metadata.Region == *req.Region {
					certAuth = append(certAuth, ca)
				} else if req.Region == nil {
					// Add All Default Certificate Authorities
					certAuth = append(certAuth, ca)
				}
			}
		}
		if len(certAuth) == 0 {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid default certificate authority"), fmt.Errorf("invalid default certificate authority for environment [%s]", req.Environment))
		}
	} else {
		certAuth = req.CertificateAuthorities
	}

	if !validator.Contains(payload.Environments, req.Environment) {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid extended key"), fmt.Errorf("invalid environment [%s]", req.Environment))
	}

	err = s.validateCertificateParameters(certAuth, req.Environment, int16(req.CertificateValidity), req.SubordinateCa)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, err.Error()), err)
	}

	if _, ok := types.CertificateRequestExtension[req.ExtendedKey]; !ok {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid extended key"), fmt.Errorf("invalid key extension [%s]", req.ExtendedKey))
	}

	if !validator.Contains(payload.ExtendedKeys, req.ExtendedKey) && !validator.Contains(payload.ExtendedKeys, "*") {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid extended key"), fmt.Errorf("invalid key extension [%s]", req.ExtendedKey))
	}

	if ok := validator.ValidateEmail(req.Email); !ok {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid email"), fmt.Errorf("invalid email [%s]", req.Email))
	}

	if len(req.Team) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid team parameter"), fmt.Errorf("invalid team [%s]", req.Team))
	}

	if req.Environment == types.Production.String() || req.NodeAttestation != nil {
		if err = verifyNodeAttestationParameters(req.NodeAttestation); err != nil {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, err.Error()), err)
		}
	}

	client_id, err := uuid.NewRandom()
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	clientToken, err := lib.GenerateClientToken(32)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	hashedClientToken, err := lib.HashPassword(clientToken)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
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
			ValidCertificateAuthorities: certAuth,
			ExtendedKey:                 req.ExtendedKey,
			CertificateValidity:         int16(req.CertificateValidity),
			SubordinateCa:               req.SubordinateCa,
			Provisioned:                 true,
			CreatedBy:                   payload.ClientId,
			CreatedAt:                   time.Now().UTC(),
		}

		if len(req.RegularExpression) != 0 {
			account_arg.RegularExpression = sql.NullString{String: req.RegularExpression, Valid: len(req.RegularExpression) != 0}
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
			ValidCertificateAuthorities: certAuth,
			ExtendedKey:                 req.ExtendedKey,
			CertificateValidity:         int16(req.CertificateValidity),
			SubordinateCa:               req.SubordinateCa,
			Provisioned:                 true,
			CreatedBy:                   payload.ClientId,
			CreatedAt:                   time.Now().UTC(),
		}

		if len(req.RegularExpression) != 0 {
			account_arg.RegularExpression = sql.NullString{String: req.RegularExpression, Valid: len(req.RegularExpression) != 0}
		}

		service, err = s.store.Writer.CreateServiceAccount(ctx, account_arg)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "error creating account"), err)
		}
	}

	response := apiv1.ProvisionServiceAccountResponse{
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
		response.RegularExpression = service.RegularExpression.String
	}

	return &response, nil
}

func (s *Service) CheckSubordinateCaRegion(subordinate_ca string, region *string, environment string, valid_certificate_authorities []string) error {
	// Service Account Does Not Contain Region Requirements for CA
	if region == nil {
		return nil
	}

	// Get Valid Certificate Authorities for Subordinate CA
	arg := db.ListValidCertificateAuthorityFromSubordinateCAParams{
		SubordinateCa: subordinate_ca,
		Environment:   environment,
	}
	certificate_authorities, err := s.store.Reader.ListValidCertificateAuthorityFromSubordinateCA(context.Background(), arg)
	if err != nil {
		return fmt.Errorf("error listing valid certificate authority from subordinate ca [%s] %s", subordinate_ca, err)
	}

	// Generate Map for Certificate Authority Regions for Subordinate CA
	subordinate_ca_regions := make(map[string]bool)
	for _, ca := range certificate_authorities {
		ca_str, ok := ca.(string)
		if !ok {
			return fmt.Errorf("certificate authority [%s] is not a string in database", ca)
		}
		region := s.acmConfig[ca_str].Region
		subordinate_ca_regions[region] = true
	}

	// Subordinate CA Across All Service Accounts Must Be In The Same Region
	if len(subordinate_ca_regions) != 1 {
		return fmt.Errorf("multiple regions present for subordinate ca [%s], cannot support region [%s]", subordinate_ca, *region)
	}

	if !subordinate_ca_regions[*region] {
		return fmt.Errorf("invalid region [%s] for subordinate ca [%s]", *region, subordinate_ca)
	}

	// Check Valid Certificate Authorities in Correct Region
	for _, ca := range valid_certificate_authorities {
		if s.acmConfig[ca].Region != *region {
			return fmt.Errorf("invalid region [%s] for certificate authority [%s]", *region, ca)
		}
	}
	return nil
}
