package certificate

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	"github.com/coinbase/baseca/internal/lib/crypto"
	"github.com/coinbase/baseca/internal/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
)

func TestGetCertificate(t *testing.T) {
	serial_number := "4ff0501e-55b2-41e0-b5b2-1f1ff6224998"
	cases := []struct {
		name  string
		req   *apiv1.CertificateSerialNumber
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.CertificateParameter, err error)
	}{
		{
			name: "OK",
			req: &apiv1.CertificateSerialNumber{
				SerialNumber: serial_number,
			},
			build: func(store *mock.MockStore) {
				resp := db.Certificate{
					SerialNumber:            serial_number,
					CommonName:              "development.example.com",
					Account:                 "example",
					Environment:             "development",
					ExtendedKey:             "EndEntityServerAuthCertificate",
					SubjectAlternativeName:  []string{"development.example.com"},
					ExpirationDate:          time.Now().UTC(),
					IssuedDate:              time.Now().UTC().Add(24 * time.Hour),
					Revoked:                 false,
					CertificateAuthorityArn: sql.NullString{String: "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", Valid: true},
				}

				store.EXPECT().GetCertificate(gomock.Any(), serial_number).Times(1).Return(&resp, nil)
			},
			check: func(t *testing.T, res *apiv1.CertificateParameter, err error) {
				require.NoError(t, err)
			},
		},
	}

	for elem := range cases {
		tc := cases[elem]

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStore(ctrl)
			tc.build(store)

			c, err := buildCertificateConfig(store)
			require.NoError(t, err)

			res, err := c.GetCertificate(context.Background(), tc.req)
			tc.check(t, res, err)
		})
	}
}

func TestOperationsSignCSR(t *testing.T) {
	cases := []struct {
		name  string
		req   func() *apiv1.OperationsSignRequest
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.SignedCertificate, err error)
	}{
		{
			name: "OK_NO_CERTIFICATE_AUTHORITY_INPUT",
			req: func() *apiv1.OperationsSignRequest {
				req := types.CertificateRequest{
					CommonName:            "development.example.com",
					SubjectAlternateNames: []string{"development.example.com"},
					SigningAlgorithm:      x509.SHA512WithRSA,
					PublicKeyAlgorithm:    x509.RSA,
					KeySize:               2048,
				}
				csr, _ := crypto.GenerateCSR(req)

				return &apiv1.OperationsSignRequest{
					CertificateSigningRequest: csr.CSR.String(),
					ServiceAccount:            "example",
					Environment:               "development",
					ExtendedKey:               "EndEntityClientAuthCertificate",
				}
			},
			build: func(store *mock.MockStore) {
				arg := db.GetServiceAccountByMetadataParams{
					ServiceAccount: "example",
					Environment:    "development",
					ExtendedKey:    "EndEntityClientAuthCertificate",
				}

				resp := []*db.Account{
					{
						ServiceAccount:              "example",
						Environment:                 "development",
						ExtendedKey:                 "EndEntityClientAuthCertificate",
						ValidCertificateAuthorities: []string{"sandbox_use1"},
					},
				}

				logArg := db.LogCertificateParams{
					Account:     "example",
					Environment: "development",
					ExtendedKey: "EndEntityClientAuthCertificate",
				}

				logResp := &db.Certificate{
					Account:     "example",
					Environment: "development",
					ExtendedKey: "EndEntityClientAuthCertificate",
				}

				store.EXPECT().GetServiceAccountByMetadata(gomock.Any(), arg).Times(1).Return(resp, nil)
				store.EXPECT().LogCertificate(gomock.Any(), &certificateLogArgMatcher{
					Account:     logArg.Account,
					Environment: logArg.Environment,
					ExtendedKey: logArg.ExtendedKey,
				}).Times(1).Return(logResp, nil)
			},
			check: func(t *testing.T, res *apiv1.SignedCertificate, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK_CERTIFICATE_AUTHORITY_INPUT",
			req: func() *apiv1.OperationsSignRequest {
				req := types.CertificateRequest{
					CommonName:            "development.example.com",
					SubjectAlternateNames: []string{"development.example.com"},
					SigningAlgorithm:      x509.SHA512WithRSA,
					PublicKeyAlgorithm:    x509.RSA,
					KeySize:               2048,
				}
				csr, _ := crypto.GenerateCSR(req)

				caParameter := &apiv1.CertificateAuthorityParameter{
					Region:        "us-east-1",
					CaArn:         "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
					SignAlgorithm: "SHA512WITHRSA",
					AssumeRole:    false,
					Validity:      30,
				}

				return &apiv1.OperationsSignRequest{
					CertificateSigningRequest: csr.CSR.String(),
					CertificateAuthority:      caParameter,
					ServiceAccount:            "example",
					Environment:               "development",
					ExtendedKey:               "EndEntityClientAuthCertificate",
				}
			},
			build: func(store *mock.MockStore) {
				logArg := db.LogCertificateParams{
					Account:     "example",
					Environment: "development",
					ExtendedKey: "EndEntityClientAuthCertificate",
				}

				logResp := &db.Certificate{
					Account:     "example",
					Environment: "development",
					ExtendedKey: "EndEntityClientAuthCertificate",
				}

				store.EXPECT().LogCertificate(gomock.Any(), &certificateLogArgMatcher{
					Account:     logArg.Account,
					Environment: logArg.Environment,
					ExtendedKey: logArg.ExtendedKey,
				}).Times(1).Return(logResp, nil)
			},
			check: func(t *testing.T, res *apiv1.SignedCertificate, err error) {
				require.NoError(t, err)
			},
		},
	}

	for elem := range cases {
		tc := cases[elem]

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStore(ctrl)
			tc.build(store)

			c, err := buildCertificateConfig(store)
			require.NoError(t, err)

			req := tc.req()
			res, err := c.OperationsSignCSR(context.Background(), req)
			tc.check(t, res, err)
		})
	}
}

type certificateLogArgMatcher struct {
	Account     string
	Environment string
	ExtendedKey string
}

func (m *certificateLogArgMatcher) Matches(x any) bool {
	if arg, ok := x.(db.LogCertificateParams); ok {
		return arg.Account == m.Account &&
			arg.Environment == m.Environment
	}
	return false
}

func (m *certificateLogArgMatcher) String() string {
	return fmt.Sprintf("Account = %v Environment = %v ExtendedKey = %v",
		m.Account, m.Environment, m.ExtendedKey)
}
