package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	db "github.com/coinbase/baseca/db/sqlc"
	"github.com/coinbase/baseca/internal/attestor/aws_iid"
	"github.com/coinbase/baseca/internal/authentication"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	"github.com/coinbase/baseca/internal/validator"
	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

const (
	_pass_auth        = "pass_authentication"
	_service_auth     = "service_authentication"
	_provisioner_auth = "provisioner_authentication"
)

func (m *Middleware) ServerAuthenticationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var auth string
	var ok bool

	methods := map[string]string{
		"/grpc.health.v1.Health/Check":                            _pass_auth,
		"/baseca.v1.Account/LoginUser":                            _pass_auth,
		"/baseca.v1.Account/UpdateUserCredentials":                _pass_auth,
		"/baseca.v1.Certificate/SignCSR":                          _service_auth,
		"/baseca.v1.Certificate/OperationsSignCSR":                _provisioner_auth,
		"/baseca.v1.Certificate/QueryCertificateMetadata":         _provisioner_auth,
		"/baseca.v1.Certificate/GetSignedIntermediateCertificate": _provisioner_auth,
		"/baseca.v1.Service/ProvisionServiceAccount":              _provisioner_auth,
		"/baseca.v1.Service/GetServiceAccountByMetadata":          _provisioner_auth,
		"/baseca.v1.Service/DeleteProvisionedServiceAccount":      _provisioner_auth,
	}

	if auth, ok = methods[info.FullMethod]; !ok {
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
			payload, err := m.auth.Verify(ctx, accessToken)
			if err != nil {
				return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), err)
			}

			userPermission := payload.Permission
			ok, err := m.enforcer.Enforce(userPermission, info.FullMethod)
			if err != nil {
				return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), err)
			}
			if !ok {
				return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), fmt.Errorf("invalid permission error %s", userPermission))
			}
			ctx = context.WithValue(ctx, types.AuthorizationPayloadKey, payload)
		}
	} else if auth == _service_auth {
		service, err := m.AuthenticateServiceAccount(ctx)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, types.ClientAuthorizationPayload, service)
	} else if auth == _provisioner_auth {
		service, err := m.AuthenticateProvisionerAccount(ctx)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, types.ClientAuthorizationPayload, service)
	}
	return handler(ctx, req)
}

func (m *Middleware) AuthenticateServiceAccount(ctx context.Context) (*authentication.ServicePayload, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Internal, "failed to retrieve metadata from context")
	}

	clientIdAuthorizationHeader, ok := md[clientIdAuthorizationHeaderKey]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
	}

	clientTokenAuthorizationHeader, ok := md[clientTokenAuthorizationHeaderKey]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
	}

	client_uuid, err := uuid.Parse(clientIdAuthorizationHeader[0])
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid authorization header")
	}

	cachedServiceAccount, err := m.authenticationCacheServiceAccount(ctx, client_uuid)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	account := cachedServiceAccount.ServiceAccount
	if err := authentication.CheckPassword(clientTokenAuthorizationHeader[0], account.ApiToken); err != nil {
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication error"), err)
	}

	for _, node_attestation := range account.NodeAttestation {
		clientIdentityDocumentHeader, ok := md[clientIdentityDocumentHeaderKey]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
		}

		switch node_attestation {
		case "AWS_IID":
			// Compare Signed Node Data with Attestation Table in Database
			attestation_err := aws_iid.AWSIidNodeAttestation(client_uuid, clientIdentityDocumentHeader[0], cachedServiceAccount.AwsIid, m.cache)
			if attestation_err != nil {
				return nil, logger.RpcError(status.Error(codes.Unauthenticated, "aws_iid attestation error"), err)
			}
		}
	}

	service := &authentication.ServicePayload{
		ServiceID:                   account.ClientID,
		ServiceAccount:              account.ServiceAccount,
		Environment:                 account.Environment,
		ValidSubjectAlternateName:   account.ValidSubjectAlternateName,
		ValidCertificateAuthorities: account.ValidCertificateAuthorities,
		CertificateValidity:         account.CertificateValidity,
		SubordinateCa:               account.SubordinateCa,
		ExtendedKey:                 account.ExtendedKey,
		SANRegularExpression:        validator.NullStringToString(&account.RegularExpression),
	}

	return service, nil
}

func (m *Middleware) AuthenticateProvisionerAccount(ctx context.Context) (*authentication.ProvisionerAccountPayload, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Internal, "failed to retrieve metadata from context")
	}

	clientIdAuthorizationHeader, ok := md[clientIdAuthorizationHeaderKey]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
	}

	clientTokenAuthorizationHeader, ok := md[clientTokenAuthorizationHeaderKey]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
	}

	client_uuid, err := uuid.Parse(clientIdAuthorizationHeader[0])
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid authorization header")
	}

	cachedProvisionerAccount, err := m.authenticationCacheProvisionerAccount(ctx, client_uuid)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	account := cachedProvisionerAccount.ProvisionerAccount
	if err := authentication.CheckPassword(clientTokenAuthorizationHeader[0], account.ApiToken); err != nil {
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication error"), err)
	}

	for _, node_attestation := range account.NodeAttestation {
		clientIdentityDocumentHeader, ok := md[clientIdentityDocumentHeaderKey]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
		}

		switch node_attestation {
		case "AWS_IID":
			// Compare Signed Node Data with Attestation Table in Database
			attestation_err := aws_iid.AWSIidNodeAttestation(client_uuid, clientIdentityDocumentHeader[0], cachedProvisionerAccount.AwsIid, m.cache)
			if attestation_err != nil {
				return nil, logger.RpcError(status.Error(codes.Unauthenticated, "aws_iid attestation error"), err)
			}
		}
	}

	service := &authentication.ProvisionerAccountPayload{
		ClientId:                   account.ClientID,
		ProvisionerAccount:         account.ProvisionerAccount,
		Environments:               account.Environments,
		ValidSubjectAlternateNames: account.ValidSubjectAlternateNames,
		MaxCertificateValidity:     uint32(account.MaxCertificateValidity),
		ExtendedKeys:               account.ExtendedKeys,
		RegularExpression:          validator.NullStringToString(&account.RegularExpression),
	}

	return service, nil
}

func (m *Middleware) authenticationCacheServiceAccount(ctx context.Context, client_uuid uuid.UUID) (*db.CachedServiceAccount, error) {
	var service_account *db.Account
	var instance_identity_document *db.AwsAttestation
	var cached_service_account db.CachedServiceAccount
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
			case types.Attestation.AWS_IID:
				instance_identity_document, err = aws_iid.GetInstanceIdentityDocument(ctx, db_reader, client_uuid)
				if err != nil {
					return &cached_service_account, fmt.Errorf("aws_iid node attestation failed: %s", err)
				}
				cached_service_account.AwsIid = *instance_identity_document
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

func (m *Middleware) authenticationCacheProvisionerAccount(ctx context.Context, client_uuid uuid.UUID) (*db.CachedProvisionerAccount, error) {
	var provisioner_account *db.Provisioner
	var instance_identity_document *db.AwsAttestation
	var cached_provisioner_account db.CachedProvisionerAccount
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
			case types.Attestation.AWS_IID:
				instance_identity_document, err = aws_iid.GetInstanceIdentityDocument(ctx, db_reader, client_uuid)
				if err != nil {
					return &cached_provisioner_account, fmt.Errorf("aws_iid node attestation failed: %s", err)
				}
				cached_provisioner_account.AwsIid = *instance_identity_document
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
