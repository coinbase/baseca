package certificate

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/coinbase/baseca/db/mock"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/types"
	baseca "github.com/coinbase/baseca/pkg/client"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestSignCSR(t *testing.T) {
	cases := []struct {
		name  string
		req   func() *apiv1.CertificateSigningRequest
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.SignedCertificate, err error)
	}{
		{
			name: "OK",
			req: func() *apiv1.CertificateSigningRequest {
				req := baseca.CertificateRequest{
					CommonName:            "example.com",
					SubjectAlternateNames: []string{"example.com"},
					SigningAlgorithm:      x509.SHA512WithRSA,
					PublicKeyAlgorithm:    x509.RSA,
					KeySize:               4096,
				}

				csr, _ := baseca.GenerateCSR(req)
				return &apiv1.CertificateSigningRequest{
					CertificateSigningRequest: csr.CSR.String(),
				}
			},
			build: func(store *mock.MockStore) {},
			check: func(t *testing.T, res *apiv1.SignedCertificate, err error) {
				require.NoError(t, err)
			}},
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

			ctx := context.WithValue(context.Background(), types.ServiceAuthenticationContextKey, &types.ServiceAccountPayload{
				ServiceID:                   uuid.New(),
				ServiceAccount:              "example",
				Environment:                 "development",
				ValidSubjectAlternateName:   []string{"example.com"},
				ValidCertificateAuthorities: []string{"sandbox_use1"},
				CertificateValidity:         int16(30),
				ExtendedKey:                 "EndEntityServerAuthCertificate",
				SubordinateCa:               "infrastructure",
			})

			req := tc.req()
			res, err := c.SignCSR(ctx, req)
			tc.check(t, res, err)
		})
	}
}
