package middleware

import (
	"context"
	"fmt"
	"strings"

	lib "github.com/coinbase/baseca/internal/lib/authentication"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	"github.com/gogo/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type AuthenticationChannel chan<- AuthenticationMetadata

type AuthenticationMetadata struct {
	Account *types.ServiceAccountPayload
	Error   error
}

type ServiceAccount struct {
	middleware *Middleware
}

func (s *ServiceAccount) Authenticate(ch <-chan context.Context, auth AuthenticationChannel) {
	for ctx := range ch {
		credentials, err := extractRequestMetadata(ctx)
		if err != nil {
			auth <- AuthenticationMetadata{Error: logger.RpcError(status.Error(codes.Internal, "authentication failed"), err)}
			return
		}

		attestation, err := s.middleware.searchServiceAccountMetadata(ctx, credentials.ClientId)
		if err != nil {
			auth <- AuthenticationMetadata{Error: logger.RpcError(status.Error(codes.Internal, "authentication failed"), err)}
			return
		}

		if err := lib.CheckPassword(credentials.ClientToken, attestation.ServiceAccount.ApiToken); err != nil {
			auth <- AuthenticationMetadata{Error: logger.RpcError(status.Error(codes.Internal, "authentication failed"), err)}
			return
		}

		instance_tags, err := validator.ConvertNullRawMessageToMap(attestation.AwsIid.InstanceTags)
		if err != nil {
			auth <- AuthenticationMetadata{Error: logger.RpcError(status.Error(codes.Internal, "authentication failed"), err)}
			return
		}

		iid := types.NodeIIDAttestation{
			Uuid: attestation.ServiceAccount.ClientID,
			Attestation: types.EC2NodeAttestation{
				ClientID:       attestation.ServiceAccount.ClientID,
				RoleArn:        attestation.AwsIid.RoleArn.String,
				AssumeRole:     attestation.AwsIid.AssumeRole.String,
				SecurityGroups: attestation.AwsIid.SecurityGroupID,
				Region:         attestation.AwsIid.Region.String,
				InstanceID:     attestation.AwsIid.InstanceID.String,
				ImageID:        attestation.AwsIid.ImageID.String,
				InstanceTags:   instance_tags,
			},
		}

		err = s.middleware.attestNode(ctx, iid, attestation.ServiceAccount.NodeAttestation)
		if err != nil {
			auth <- AuthenticationMetadata{Error: logger.RpcError(status.Error(codes.Internal, "attestation failed"), err)}
			return
		}

		account := &types.ServiceAccountPayload{
			ServiceID:                   attestation.ServiceAccount.ClientID,
			ServiceAccount:              attestation.ServiceAccount.ServiceAccount,
			Environment:                 attestation.ServiceAccount.Environment,
			ValidSubjectAlternateName:   attestation.ServiceAccount.ValidSubjectAlternateName,
			ValidCertificateAuthorities: attestation.ServiceAccount.ValidCertificateAuthorities,
			CertificateValidity:         attestation.ServiceAccount.CertificateValidity,
			SubordinateCa:               attestation.ServiceAccount.SubordinateCa,
			ExtendedKey:                 attestation.ServiceAccount.ExtendedKey,
			SANRegularExpression:        validator.NullStringToString(&attestation.ServiceAccount.RegularExpression),
		}
		auth <- AuthenticationMetadata{Account: account}
	}
}

type ProvisionerAccount struct {
	middleware *Middleware
}

func (p *ProvisionerAccount) Authenticate(ctx context.Context) (interface{}, error) {
	credentials, err := extractRequestMetadata(ctx)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "authentication failed"), err)
	}

	attestation, err := p.middleware.serachProvisionerAccountAttestation(ctx, credentials.ClientId)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "authentication failed"), err)
	}

	if err := lib.CheckPassword(credentials.ClientToken, attestation.ProvisionerAccount.ApiToken); err != nil {
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), err)
	}

	instance_tags, err := validator.ConvertNullRawMessageToMap(attestation.AwsIid.InstanceTags)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "error querying attestation tags"), err)
	}

	iid := types.NodeIIDAttestation{
		Uuid: attestation.ProvisionerAccount.ClientID,
		Attestation: types.EC2NodeAttestation{
			ClientID:       attestation.ProvisionerAccount.ClientID,
			RoleArn:        attestation.AwsIid.RoleArn.String,
			AssumeRole:     attestation.AwsIid.AssumeRole.String,
			SecurityGroups: attestation.AwsIid.SecurityGroupID,
			Region:         attestation.AwsIid.Region.String,
			InstanceID:     attestation.AwsIid.InstanceID.String,
			ImageID:        attestation.AwsIid.ImageID.String,
			InstanceTags:   instance_tags,
		},
	}

	err = p.middleware.attestNode(ctx, iid, attestation.ProvisionerAccount.NodeAttestation)
	if err != nil {
		return nil, err
	}

	account := &types.ProvisionerAccountPayload{
		ClientId:                   attestation.ProvisionerAccount.ClientID,
		ProvisionerAccount:         attestation.ProvisionerAccount.ProvisionerAccount,
		Environments:               attestation.ProvisionerAccount.Environments,
		ValidSubjectAlternateNames: attestation.ProvisionerAccount.ValidSubjectAlternateNames,
		MaxCertificateValidity:     uint32(attestation.ProvisionerAccount.MaxCertificateValidity),
		ExtendedKeys:               attestation.ProvisionerAccount.ExtendedKeys,
		RegularExpression:          validator.NullStringToString(&attestation.ProvisionerAccount.RegularExpression),
	}
	return account, nil
}

type UserAccount struct {
	middleware *Middleware
	info       *grpc.UnaryServerInfo
}

func (u *UserAccount) Authenticate(ctx context.Context) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Internal, "failed to retrieve metadata from context")
	}

	authorizationHeader, ok := md[authorizationHeaderKey]
	if !ok || len(authorizationHeader) == 0 {
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), fmt.Errorf("request header empty: %s", authorizationHeaderKey))
	}

	if len(authorizationHeader) != 0 {
		fields := strings.Fields(authorizationHeader[0])
		if len(fields) < 2 {
			return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), fmt.Errorf("authorization header not provided"))
		}

		authorizationType := strings.ToLower(fields[0])
		if authorizationType != authorizationTypeBearer {
			return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), fmt.Errorf("authorization header not provided"))
		}

		accessToken := fields[1]
		payload, err := u.middleware.auth.Verify(ctx, accessToken)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), err)
		}

		userPermission := payload.Permission
		ok, err := u.middleware.enforcer.Enforce(userPermission, u.info.FullMethod)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), err)
		}
		if !ok {
			return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), fmt.Errorf("invalid permission error %s", userPermission))
		}
		return payload, nil
	}
	return nil, nil
}
