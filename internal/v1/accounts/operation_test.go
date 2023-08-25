package accounts

import (
	"context"
	"fmt"
	"testing"

	"github.com/coinbase/baseca/db/mock"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestDeleteServiceAccount(t *testing.T) {
	service_account_id := "030984ac-e8b3-4f6e-83b2-03ecc81c0477"
	client_id, err := uuid.Parse(service_account_id)
	require.NoError(t, err)

	cases := []struct {
		name  string
		req   *apiv1.AccountId
		build func(store *mock.MockStore)
		check func(t *testing.T, res *emptypb.Empty, err error)
	}{
		{
			name: "OK",
			req: &apiv1.AccountId{
				Uuid: service_account_id,
			},
			build: func(store *mock.MockStore) {
				store.EXPECT().TxDeleteServiceAccount(gomock.Any(), client_id).Times(1).Return(nil)
			},
			check: func(t *testing.T, res *emptypb.Empty, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "INVALID_UUID",
			req: &apiv1.AccountId{
				Uuid: "random_string",
			},
			build: func(store *mock.MockStore) {},
			check: func(t *testing.T, res *emptypb.Empty, err error) {
				require.Error(t, err)
				require.EqualError(t, err, "rpc error: code = InvalidArgument desc = invalid uuid parameter")
			},
		},
		{
			name: "DB_ERROR",
			req: &apiv1.AccountId{
				Uuid: service_account_id,
			},
			build: func(store *mock.MockStore) {
				store.EXPECT().TxDeleteServiceAccount(gomock.Any(), client_id).Times(1).Return(fmt.Errorf("internal server error"))
			},
			check: func(t *testing.T, res *emptypb.Empty, err error) {
				require.Error(t, err)
				require.EqualError(t, err, "rpc error: code = Internal desc = internal server error")
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

			c, err := buildAccountsConfig(store)
			require.NoError(t, err)

			res, err := c.DeleteServiceAccount(context.Background(), tc.req)
			tc.check(t, res, err)
		})
	}
}
