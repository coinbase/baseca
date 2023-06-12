package certificate

import (
	"context"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/logger"
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
		return nil, status.Error(codes.InvalidArgument, "missing common name (cn)")
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
			CertificateAuthorityArn: certificate.CertificateAuthorityArn.String})
	}
	return &pbCertificates, nil
}
