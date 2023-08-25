package certificate

import (
	"context"
	"testing"

	"github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestQueryCertificateMetadata(t *testing.T) {

	cases := []struct {
		name  string
		req   *apiv1.QueryCertificateMetadataRequest
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.CertificatesParameter, err error)
	}{
		{
			name: "OK",
			req: &apiv1.QueryCertificateMetadataRequest{
				Account:     "example",
				Environment: "sandbox",
			},
			build: func(store *mock.MockStore) {
				arg := db.GetSignedCertificateByMetadataParams{
					SerialNumber: "%",
					Account:      "example",
					Environment:  "sandbox",
					ExtendedKey:  "%",
				}

				resp := []*db.Certificate{
					{
						Account:     "example",
						Environment: "sandbox",
					},
				}
				store.EXPECT().GetSignedCertificateByMetadata(gomock.Any(), arg).Times(1).Return(resp, nil)
			},
			check: func(t *testing.T, res *apiv1.CertificatesParameter, err error) {
				require.NoError(t, err)
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := mock.NewMockStore(ctrl)

	for elem := range cases {
		tc := cases[elem]

		t.Run(tc.name, func(t *testing.T) {
			tc.build(store)

			c, err := buildCertificateConfig(store)
			require.NoError(t, err)

			res, err := c.QueryCertificateMetadata(context.Background(), tc.req)
			tc.check(t, res, err)
		})
	}
}
