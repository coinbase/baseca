package certificate

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

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
					CommonName:              "example.coinbase.com",
					Account:                 "example",
					Environment:             "development",
					ExtendedKey:             "EndEntityServerAuthCertificate",
					SubjectAlternativeName:  []string{"example.coinbase.com"},
					ExpirationDate:          time.Now(),
					IssuedDate:              time.Now().Add(24 * time.Hour),
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
