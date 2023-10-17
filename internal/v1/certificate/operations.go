package certificate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	pca_types "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/client/acmpca"
	lib "github.com/coinbase/baseca/internal/lib/authentication"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	"github.com/gogo/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	_revocationReason = []string{
		"AFFILIATION_CHANGED",
		"CESSATION_OF_OPERATION",
		"A_A_COMPROMISE",
		"PRIVILEGE_WITHDRAWN",
		"SUPERSEDED",
		"UNSPECIFIED",
		"KEY_COMPROMISE",
		"CERTIFICATE_AUTHORITY_COMPROMISE",
	}

	_default_signing_algorithm = "SHA512WITHRSA"
	_default_validity          = 365
)

func (c *Certificate) RevokeCertificate(ctx context.Context, req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	var parameters types.CertificateParameters
	var processed *pca_types.RequestAlreadyProcessedException

	if _, ok := ctx.Value(types.UserAuthenticationContextKey).(*lib.Claims); !ok {
		return nil, status.Error(codes.InvalidArgument, "authentication error")
	}
	uuid := ctx.Value(types.UserAuthenticationContextKey).(*lib.Claims).Subject

	certificate, err := c.store.Reader.GetCertificate(ctx, req.SerialNumber)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	for _, ca := range c.acmConfig {
		if ca.CaArn == certificate.CertificateAuthorityArn.String {
			parameters = types.CertificateParameters{
				Region:     ca.Region,
				CaArn:      ca.CaArn,
				AssumeRole: ca.AssumeRole,
				RoleArn:    ca.RoleArn,
				Validity:   ca.CaActiveDay,
			}
		}
	}

	// c.pca Mock Private CA
	if c.pca == nil {
		client, err := acmpca.NewPrivateCaClient(parameters)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "acm pca client error"), err)
		}
		c.pca = client
	}

	if !validator.Contains(_revocationReason, req.RevocationReason) {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid revocation"), fmt.Errorf("%s invalid revocation parameter", req.RevocationReason))
	}
	_, err = c.pca.RevokeCertificate(certificate.CertificateAuthorityArn.String, certificate.SerialNumber, req.RevocationReason)
	if err != nil {
		if errors.As(err, &processed) {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "certificate already revoked"), err)
		}
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	arg := db.RevokeIssuedCertificateSerialNumberParams{
		SerialNumber: req.SerialNumber,
		RevokeDate:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
		RevokedBy:    sql.NullString{String: uuid.String(), Valid: true},
	}

	err = c.store.Writer.RevokeIssuedCertificateSerialNumber(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return &apiv1.RevokeCertificateResponse{
		SerialNumber:   req.SerialNumber,
		RevocationDate: timestamppb.New(arg.RevokeDate.Time),
		Status:         req.RevocationReason,
	}, nil
}

func (c *Certificate) OperationsSignCSR(ctx context.Context, req *apiv1.OperationsSignRequest) (*apiv1.SignedCertificate, error) {
	var certificateAuthorityParameters *apiv1.CertificateAuthorityParameter

	if err := c.validateCsrParameters(req); err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid certificate signing request (csr)"), err)
	}

	if _, ok := types.CertificateRequestExtension[req.ExtendedKey]; !ok {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid certificate extended key"), fmt.Errorf("invalid certificate extended key"))
	}

	// Query Account Metadata to Discover Upstream Private CA
	if req.CertificateAuthority == nil {
		arg := db.GetServiceAccountByMetadataParams{
			ServiceAccount: req.ServiceAccount,
			Environment:    req.Environment,
			ExtendedKey:    req.ExtendedKey,
		}

		serviceAccount, err := c.store.Reader.GetServiceAccountByMetadata(ctx, arg)
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.Internal, "error issuing certificate [OperationsSignCSR]"), fmt.Errorf("error querying service account metadata [%s]: %s", req.ServiceAccount, err))
		}

		if len(serviceAccount) != 1 {
			return nil, logger.RpcError(status.Error(codes.Internal, "error querying service account(s)"), fmt.Errorf("[%d] service accounts found for [%s] in environment [%s], cleanup before issuing long-lived certificate", len(serviceAccount), req.ServiceAccount, req.Environment))
		}

		accountMetadata := serviceAccount[0]
		certificateAuthority := accountMetadata.ValidCertificateAuthorities[0]
		certificateAuthorityParameters = &apiv1.CertificateAuthorityParameter{
			Region:        c.acmConfig[certificateAuthority].Region,
			CaArn:         c.acmConfig[certificateAuthority].CaArn,
			AssumeRole:    c.acmConfig[certificateAuthority].AssumeRole,
			RoleArn:       c.acmConfig[certificateAuthority].RoleArn,
			Validity:      int32(_default_validity),
			SignAlgorithm: _default_signing_algorithm,
		}
	} else {
		expirationDate := time.Now().UTC().AddDate(0, 0, int(req.CertificateAuthority.Validity)).UTC()
		if expirationDate.Before(time.Now().UTC().Add(time.Minute).UTC()) {
			return nil, logger.RpcError(status.Error(codes.Internal, "invalid certificate validity"), fmt.Errorf("invalid certificate validity [%s]", req.ServiceAccount))
		}

		certificateAuthorityParameters = &apiv1.CertificateAuthorityParameter{
			Region:        req.CertificateAuthority.Region,
			CaArn:         req.CertificateAuthority.CaArn,
			AssumeRole:    req.CertificateAuthority.AssumeRole,
			RoleArn:       req.CertificateAuthority.RoleArn,
			Validity:      int32(req.CertificateAuthority.Validity),
			SignAlgorithm: req.CertificateAuthority.SignAlgorithm,
		}
	}
	// c.pca Mock Private CA
	if c.pca == nil {
		client, err := acmpca.NewPrivateCaClient(types.CertificateParameters{
			AssumeRole: certificateAuthorityParameters.AssumeRole,
			RoleArn:    certificateAuthorityParameters.RoleArn,
			Region:     certificateAuthorityParameters.Region,
		})
		if err != nil {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid parameters for acm pca client"), err)
		}
		c.pca = client
	}

	certificate, err := c.pca.IssueCertificateFromTemplate(certificateAuthorityParameters, []byte(req.CertificateSigningRequest), types.CertificateRequestExtension[req.ExtendedKey].TemplateArn)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "error issuing certificate"), err)
	}

	// Only Common Name (CN) Exists in CSR
	if len(certificate.DNSNames) == 0 {
		certificate.DNSNames = append(certificate.DNSNames, certificate.Subject.CommonName)
	}

	arg := db.LogCertificateParams{
		SerialNumber:            certificate.SerialNumber.Text(16),
		Account:                 req.ServiceAccount,
		Environment:             req.Environment,
		ExtendedKey:             req.ExtendedKey,
		CommonName:              certificate.Subject.CommonName,
		SubjectAlternativeName:  certificate.DNSNames,
		ExpirationDate:          certificate.NotAfter.UTC(),
		IssuedDate:              certificate.NotBefore.UTC(),
		CertificateAuthorityArn: sql.NullString{String: certificateAuthorityParameters.CaArn, Valid: len(certificateAuthorityParameters.CaArn) != 0},
	}

	metadata, err := c.store.Writer.LogCertificate(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	signedCertificate, err := convertX509toString(certificate.Raw)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return &apiv1.SignedCertificate{
		Certificate: signedCertificate.String(),
		Metadata: &apiv1.CertificateParameter{
			SerialNumber:            metadata.SerialNumber,
			Account:                 metadata.Account,
			Environment:             metadata.Environment,
			ExtendedKey:             metadata.ExtendedKey,
			CommonName:              metadata.CommonName,
			SubjectAlternativeName:  metadata.SubjectAlternativeName,
			ExpirationDate:          timestamppb.New(metadata.ExpirationDate),
			IssuedDate:              timestamppb.New(metadata.IssuedDate),
			CertificateAuthorityArn: metadata.CertificateAuthorityArn.String,
		},
	}, nil
}
