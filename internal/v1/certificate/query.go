package certificate

import (
	"context"
	"database/sql"
	"fmt"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	"github.com/gogo/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (c *Certificate) GetCertificate(ctx context.Context, req *apiv1.CertificateSerialNumber) (*apiv1.CertificateParameter, error) {
	certificate, err := c.store.Reader.GetCertificate(ctx, req.SerialNumber)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "certificate not found"), err)
	}
	return &apiv1.CertificateParameter{
		SerialNumber:            certificate.SerialNumber,
		Account:                 certificate.Account,
		Environment:             certificate.Environment,
		ExtendedKey:             certificate.ExtendedKey,
		CommonName:              certificate.CommonName,
		SubjectAlternativeName:  certificate.SubjectAlternativeName,
		ExpirationDate:          timestamppb.New(certificate.ExpirationDate),
		IssuedDate:              timestamppb.New(certificate.IssuedDate),
		Revoked:                 certificate.Revoked,
		RevokedBy:               certificate.RevokedBy.String,
		RevokeDate:              timestamppb.New(certificate.RevokeDate.Time),
		CertificateAuthorityArn: certificate.CertificateAuthorityArn.String,
	}, nil
}

func (c *Certificate) ListCertificates(ctx context.Context, req *apiv1.ListCertificatesRequest) (*apiv1.CertificatesParameter, error) {
	var pbCertificates apiv1.CertificatesParameter

	if len(req.CommonName) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "missing common name (cn)"), fmt.Errorf("missing common name (cn)"))
	}

	arg := db.ListCertificateSubjectAlternativeNameParams{
		CommonName: req.CommonName,
		Limit:      req.PageSize,
		Offset:     (req.PageId - 1) * req.PageSize,
	}

	certificates, err := c.store.Reader.ListCertificateSubjectAlternativeName(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	for _, certificate := range certificates {
		pbCertificates.Certificates = append(pbCertificates.Certificates, &apiv1.CertificateParameter{
			SerialNumber:            certificate.SerialNumber,
			Account:                 certificate.Account,
			Environment:             certificate.Environment,
			ExtendedKey:             certificate.ExtendedKey,
			CommonName:              certificate.CommonName,
			SubjectAlternativeName:  certificate.SubjectAlternativeName,
			ExpirationDate:          timestamppb.New(certificate.ExpirationDate),
			IssuedDate:              timestamppb.New(certificate.IssuedDate),
			Revoked:                 certificate.Revoked,
			RevokedBy:               certificate.RevokedBy.String,
			RevokeDate:              timestamppb.New(certificate.RevokeDate.Time),
			CertificateAuthorityArn: certificate.CertificateAuthorityArn.String,
		})
	}
	return &pbCertificates, nil
}

func (c *Certificate) QueryCertificateMetadata(ctx context.Context, req *apiv1.QueryCertificateMetadataRequest) (*apiv1.CertificatesParameter, error) {
	var serialNumber, account, environment, extendedKey string
	var san []string
	var pbCertificates apiv1.CertificatesParameter

	if len(req.Account) == 0 && len(req.SerialNumber) == 0 && len(req.Environment) == 0 && len(req.ExtendedKey) == 0 && len(req.SubjectAlternativeName) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid parameters"), fmt.Errorf("invalid parameters nil or empty"))
	}

	if len(req.SerialNumber) != 0 {
		if !validator.ValidateInput(req.SerialNumber) {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid serial number format"), fmt.Errorf("invalid serial number: %s", req.SerialNumber))
		}
		serialNumber = req.SerialNumber
	} else {
		serialNumber = "%"
	}

	if len(req.Account) != 0 {
		account = req.Account
	} else {
		account = "%"
	}

	if len(req.Environment) != 0 {
		if _, ok := validator.CertificateAuthorityEnvironments[req.Environment]; !ok {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid environment"), fmt.Errorf("invalid environment: %s", req.Environment))
		}

		environment = req.Environment
	} else {
		environment = "%"
	}

	if len(req.ExtendedKey) != 0 {
		if _, ok := types.CertificateRequestExtension[req.ExtendedKey]; !ok {
			return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid extended key"), fmt.Errorf("invalid extended key: %s", req.ExtendedKey))

		}
		extendedKey = req.ExtendedKey
	} else {
		extendedKey = "%"
	}

	if len(req.SubjectAlternativeName) > 1 {
		san = validator.SanitizeInput(req.SubjectAlternativeName)
	}

	arg := db.GetSignedCertificateByMetadataParams{
		SerialNumber: serialNumber,
		Account:      account,
		Environment:  environment,
		ExtendedKey:  extendedKey,
	}

	certificates, err := c.store.Reader.GetSignedCertificateByMetadata(ctx, arg)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, logger.RpcError(status.Error(codes.NotFound, "certificate not found"), err)
		}
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	for _, certificate := range certificates {
		if len(san) == 0 {
			pbCertificates.Certificates = append(pbCertificates.Certificates, &apiv1.CertificateParameter{
				SerialNumber:            certificate.SerialNumber,
				Account:                 certificate.Account,
				Environment:             certificate.Environment,
				ExtendedKey:             certificate.ExtendedKey,
				CommonName:              certificate.CommonName,
				SubjectAlternativeName:  certificate.SubjectAlternativeName,
				ExpirationDate:          timestamppb.New(certificate.ExpirationDate),
				IssuedDate:              timestamppb.New(certificate.IssuedDate),
				Revoked:                 certificate.Revoked,
				RevokedBy:               certificate.RevokedBy.String,
				RevokeDate:              timestamppb.New(certificate.RevokeDate.Time),
				CertificateAuthorityArn: certificate.CertificateAuthorityArn.String,
			})
		} else {
			check := true
			for _, a := range san {
				if !validator.Contains(certificate.SubjectAlternativeName, a) {
					check = false
					break
				}
			}

			if check {
				pbCertificates.Certificates = append(pbCertificates.Certificates, &apiv1.CertificateParameter{
					SerialNumber:            certificate.SerialNumber,
					Account:                 certificate.Account,
					Environment:             certificate.Environment,
					ExtendedKey:             certificate.ExtendedKey,
					CommonName:              certificate.CommonName,
					SubjectAlternativeName:  certificate.SubjectAlternativeName,
					ExpirationDate:          timestamppb.New(certificate.ExpirationDate),
					IssuedDate:              timestamppb.New(certificate.IssuedDate),
					Revoked:                 certificate.Revoked,
					RevokedBy:               certificate.RevokedBy.String,
					RevokeDate:              timestamppb.New(certificate.RevokeDate.Time),
					CertificateAuthorityArn: certificate.CertificateAuthorityArn.String,
				})
			}
		}
	}

	return &pbCertificates, nil
}
