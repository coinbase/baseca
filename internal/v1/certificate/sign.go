package certificate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/client/acmpca"
	"github.com/coinbase/baseca/internal/config"
	"github.com/coinbase/baseca/internal/lib/crypto"
	"github.com/coinbase/baseca/internal/lib/util"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	baseca "github.com/coinbase/baseca/pkg/client"
	lib "github.com/coinbase/baseca/pkg/types"
	"github.com/gogo/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (c *Certificate) SignCSR(ctx context.Context, req *apiv1.CertificateSigningRequest) (*apiv1.SignedCertificate, error) {
	var service *types.ServiceAccountPayload
	var ok bool

	if service, ok = ctx.Value(types.ServiceAuthenticationContextKey).(*types.ServiceAccountPayload); !ok {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), fmt.Errorf("service payload malformatted: %+v", service))
	}

	csrPem, _ := pem.Decode([]byte(req.CertificateSigningRequest))
	if csrPem == nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "certificate signing request (csr) invalid format"), fmt.Errorf("error decoding certificate signing request (csr): %+v", service))
	}

	csr, err := x509.ParseCertificateRequest(csrPem.Bytes)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "certificate signing request (csr) invalid format"), err)
	}

	if c.redis.Limit != 0 {
		if !validator.Contains(c.redis.Excluded, service.ServiceAccount) {
			err = c.rateLimit(ctx, csr)
			if err != nil {
				return nil, logger.RpcError(status.Error(codes.ResourceExhausted, "rate limit exceeded"), err)
			}
		}
	}

	err = c.validateCertificateRequestParameters(csr, *service)
	if err != nil {
		return nil, err
	}

	certificate, err := c.requestCertificate(ctx, service, csr)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, fmt.Sprintf("error signing certificate request %s", err.Error())), err)
	}

	return &apiv1.SignedCertificate{
		Certificate:                  certificate.Certificate,
		IntermediateCertificateChain: certificate.IntermediateCertificateChain,
		CertificateChain:             certificate.RootCertificateChain,
		Metadata: &apiv1.CertificateParameter{
			SerialNumber:            certificate.Metadata.SerialNumber,
			CommonName:              certificate.Metadata.CommonName,
			SubjectAlternativeName:  certificate.Metadata.SubjectAlternativeName,
			ExpirationDate:          timestamppb.New(certificate.Metadata.ExpirationDate),
			IssuedDate:              timestamppb.New(certificate.Metadata.IssuedDate),
			Revoked:                 certificate.Metadata.Revoked,
			RevokedBy:               certificate.Metadata.RevokedBy,
			RevokeDate:              timestamppb.New(certificate.Metadata.RevokeDate),
			CertificateAuthorityArn: certificate.Metadata.CertificateAuthorityArn,
		},
	}, nil

}

func (c *Certificate) requestCertificate(ctx context.Context, authPayload *types.ServiceAccountPayload, certificateRequest *x509.CertificateRequest) (*types.CertificateResponseData, error) {
	var subordinate *types.CertificateAuthority
	var parameters baseca.CertificateRequest
	var csr *bytes.Buffer
	var err error

	intermediateCa := fmt.Sprintf("%s_%s", authPayload.SubordinateCa, authPayload.Environment)

	err = checkLockfile(intermediateCa)
	if err != nil {
		return nil, err
	}

	subordinate, err = loadSubordinateCaParameters(intermediateCa, authPayload)
	if err != nil {
		err = createServiceDirectory(intermediateCa)
		if err != nil {
			return nil, err
		}

		err = util.GenerateLockfile(intermediateCa)
		if err != nil {
			return nil, err
		}

		signingAlgorithm, ok := lib.ValidSignatures[c.ca.SigningAlgorithm]
		if !ok {
			return nil, fmt.Errorf("invalid signing algorithm: %s", c.ca.SigningAlgorithm)
		}

		parameters = baseca.CertificateRequest{
			CommonName:            intermediateCa,
			SubjectAlternateNames: []string{intermediateCa},
			SigningAlgorithm:      signingAlgorithm.Common,
			PublicKeyAlgorithm:    lib.PublicKeyAlgorithmStrings[c.ca.KeyAlgorithm].Algorithm,
			KeySize:               c.ca.KeySize,
			DistinguishedName: baseca.DistinguishedName{
				Country:            []string{c.ca.Country},
				Province:           []string{c.ca.Province},
				Locality:           []string{c.ca.Locality},
				Organization:       []string{c.ca.Organization},
				OrganizationalUnit: []string{c.ca.OrganizationUnit},
			},
		}

		signingRequest, err := baseca.GenerateCSR(parameters)
		if err != nil {
			return nil, err
		}

		err = crypto.WriteKeyToFile(intermediateCa, signingRequest.PrivateKey)
		if err != nil {
			return nil, err
		}

		csr = signingRequest.CSR

		// Issue Subordinate CA
		err = c.issueSubordinate(authPayload, csr, intermediateCa)
		if err != nil {
			return nil, fmt.Errorf("error generating subordinate ca [%s]: %s", intermediateCa, err)
		}
		err = util.RemoveLockfile(intermediateCa)
		if err != nil {
			return nil, err
		}

		subordinate, err = loadSubordinateCaParameters(intermediateCa, authPayload)
		if err != nil {
			return nil, err
		}

		certificate, err := c.issueEndEntityCertificate(authPayload, subordinate, certificateRequest)
		if err != nil {
			return nil, fmt.Errorf("error issuing end entity certificate: %s", err)
		} else {
			return certificate, nil
		}
	} else {
		// Issue End Entity Certificate
		certificate, err := c.issueEndEntityCertificate(authPayload, subordinate, certificateRequest)
		if err != nil {
			return nil, fmt.Errorf("error issuing end entity certificate: %s", err)
		} else {
			return certificate, nil
		}
	}
}

func (c *Certificate) validateCertificateRequestParameters(csr *x509.CertificateRequest, auth types.ServiceAccountPayload) error {
	if err := csr.CheckSignature(); err != nil {
		return logger.RpcError(status.Error(codes.InvalidArgument, "invalid signature for certificate signing request (csr)"), err)
	}

	if len(csr.Subject.CommonName) == 0 {
		return logger.RpcError(status.Error(codes.InvalidArgument, "common name (cn) missing from certificate signing request (csr)"), fmt.Errorf("%s", csr.Subject))
	}

	subjectAlternativeNames := append(csr.DNSNames, csr.Subject.CommonName)
	err := validator.ValidateSubjectAlternateNames(subjectAlternativeNames, auth.ValidSubjectAlternateName, auth.SANRegularExpression)
	if err != nil {
		return logger.RpcError(status.Error(codes.InvalidArgument, "invalid subject alternative name(s) in certificate signing request (csr)"), err)
	}

	for _, certificate_authority := range auth.ValidCertificateAuthorities {
		if (c.acmConfig[certificate_authority] == config.SubordinateCertificate{}) {
			return logger.RpcError(status.Error(codes.InvalidArgument, "invalid certificate authority (ca)"), fmt.Errorf("certificate authority: %s", certificate_authority))
		}
	}
	return nil
}

func (c *Certificate) rateLimit(ctx context.Context, certificateRequest *x509.CertificateRequest) error {
	mapping := make(map[string]bool)
	mapping[certificateRequest.Subject.CommonName] = true
	for _, fqdn := range certificateRequest.DNSNames {
		mapping[fqdn] = true
	}

	for domain := range mapping {
		err := c.redis.Increment(ctx, domain, 1)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Certificate) issueSubordinate(auth *types.ServiceAccountPayload, certificate_signing_request *bytes.Buffer, service_name string) error {
	var ca_certificate *x509.Certificate
	var err error

	// Handle Multi-Region Failover
	for _, ca := range auth.ValidCertificateAuthorities {
		ca_parameters := c.buildCertificateAuthorityParameters(ca)

		// c.pca Mock Private CA
		if c.pca == nil {
			client, err := acmpca.NewPrivateCaClient(ca_parameters)
			if err != nil {
				return err
			}
			c.pca = client
		}

		ca_certificate, err = c.pca.IssueSubordinateCertificate(ca_parameters, c.ca.SigningAlgorithm, certificate_signing_request.Bytes())
		if err != nil {
			logger.DefaultLogger.Error(err.Error())

			// Build ACM Client for Other Regions
			continue
		}

		certificate_chain, err := c.pca.GetSubordinateCAChain(ca_parameters.CaArn)
		if err != nil {
			return err
		}

		err = crypto.WriteSubordinateCaParameters(service_name, ca_certificate, ca_parameters, certificate_chain)
		if err != nil {
			return err
		}
		return nil
	}
	return nil
}
