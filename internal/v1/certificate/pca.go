package certificate

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	math_rand "math/rand"
	"time"

	db "github.com/coinbase/baseca/db/sqlc"
	"github.com/coinbase/baseca/internal/authentication"
	"github.com/coinbase/baseca/internal/client/firehose"
	"github.com/coinbase/baseca/internal/lib/crypto"
	"github.com/coinbase/baseca/internal/types"
)

func (c *Certificate) buildCertificateAuthorityParameters(certificate_authority string) types.CertificateParameters {
	return types.CertificateParameters{
		Region:     c.acmConfig[certificate_authority].Region,
		CaArn:      c.acmConfig[certificate_authority].CaArn,
		AssumeRole: c.acmConfig[certificate_authority].AssumeRole,
		RoleArn:    c.acmConfig[certificate_authority].RoleArn,
		Validity:   c.acmConfig[certificate_authority].CaActiveDay,
		RootCa:     c.acmConfig[certificate_authority].RootCa,
	}
}

func (c *Certificate) issueEndEntityCertificate(auth *authentication.ServicePayload, ca_certificate *types.CertificateAuthority, request_csr *x509.CertificateRequest) (*db.CertificateResponseData, error) {
	block := make([]byte, 20)
	_, err := rand.Read(block[:])
	if err != nil {
		return nil, err
	}
	math_rand.Seed(int64(binary.LittleEndian.Uint64(block[:])))

	output := big.NewInt(0).SetBytes(block)
	issuedDate := time.Now().UTC()

	expirationDate := time.Now().UTC().AddDate(0, 0, int(auth.CertificateValidity)).UTC()
	if expirationDate.Before(time.Now().UTC().Add(time.Minute).UTC()) {
		return nil, err
	}

	certificateTemplate := x509.Certificate{
		DNSNames:           request_csr.DNSNames,
		Signature:          request_csr.Signature,
		SignatureAlgorithm: request_csr.SignatureAlgorithm,
		PublicKeyAlgorithm: request_csr.PublicKeyAlgorithm,
		PublicKey:          request_csr.PublicKey,
		SerialNumber:       output,
		Issuer:             ca_certificate.Certificate.Subject,
		Subject:            request_csr.Subject,
		NotBefore:          issuedDate,
		NotAfter:           expirationDate,
		KeyUsage:           types.CertificateRequestExtension[auth.ExtendedKey].KeyUsage,
		ExtKeyUsage:        types.CertificateRequestExtension[auth.ExtendedKey].ExtendedKeyUsage,
	}

	if len(c.ocsp) != 0 {
		certificateTemplate.OCSPServer = c.ocsp
	}

	certificateAuthorityRaw := ca_certificate.Certificate.Raw
	pk, err := crypto.ReturnPrivateKey(*ca_certificate.AsymmetricKey)
	if err != nil {
		return nil, err
	}
	certificateRaw, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, ca_certificate.Certificate, request_csr.PublicKey, pk)
	if err != nil {
		return nil, err
	}

	leafCertificate, err := x509.ParseCertificate(certificateRaw)
	if err != nil {
		return nil, fmt.Errorf("error parsing leaf certificate data")
	}

	caPath := fmt.Sprintf("%s_%s", auth.SubordinateCa, auth.Environment)
	certificate, intermediate_chain, root_chain, err := crypto.BuildCertificateChain(caPath, certificateRaw, certificateAuthorityRaw)
	if err != nil {
		return nil, err
	}

	certificate_data := types.CertificateMetadata{
		// Serial Number: Convert Base 10 *bit.Int output to Base 16:
		SerialNumber:            leafCertificate.SerialNumber.Text(16),
		CommonName:              request_csr.Subject.CommonName,
		SubjectAlternativeName:  request_csr.DNSNames,
		ExpirationDate:          expirationDate,
		IssuedDate:              issuedDate,
		CaSerialNumber:          ca_certificate.SerialNumber,
		CertificateAuthorityArn: ca_certificate.CertificateAuthorityArn,
		Timestamp:               time.Now().UTC(),
	}

	event := firehose.ForwardedEventUploadEvent{
		SerialNumber: leafCertificate.SerialNumber.Text(16),
		Metadata: firehose.Metadata{
			CommonName:              certificate_data.CommonName,
			SubjectAlternateName:    certificate_data.SubjectAlternativeName,
			CertificateExpiration:   certificate_data.ExpirationDate,
			IssuedDate:              certificate_data.IssuedDate,
			CaSerialNumber:          certificate_data.CaSerialNumber,
			CertificateAuthorityArn: certificate_data.CertificateAuthorityArn,
		},
	}

	_, err = c.firehose.Stream(context.Background(), event)
	if err != nil {
		return nil, err
	}

	return &db.CertificateResponseData{
		Certificate:                  certificate.String(),
		IntermediateCertificateChain: intermediate_chain.String(),
		RootCertificateChain:         root_chain.String(),
		Metadata:                     certificate_data,
	}, nil
}
