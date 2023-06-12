package accounts

import (
	"context"
	"fmt"
	"testing"

	"github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestListServiceAccounts(t *testing.T) {
	const (
		pageId   = 1
		pageSize = 5
	)

	param := db.ListServiceAccountsParams{
		Limit:  pageSize,
		Offset: (pageId - 1) * pageSize,
	}

	clientId, err := uuid.NewRandom()
	require.NoError(t, err)

	cases := []struct {
		name  string
		req   *apiv1.QueryParameter
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.ServiceAccounts, err error)
	}{
		{
			name: "OK_NO_SERVICE_ACCOUNT",
			req: &apiv1.QueryParameter{
				PageId:   1,
				PageSize: 5,
			},
			build: func(store *mock.MockStore) {
				store.EXPECT().ListServiceAccounts(gomock.Any(), param).Times(1).Return([]*db.Account{}, nil)
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK_NO_NODE_ATTESTATION",
			req: &apiv1.QueryParameter{
				PageId:   1,
				PageSize: 5,
			},
			build: func(store *mock.MockStore) {
				account := db.Account{
					ClientID:        clientId,
					NodeAttestation: []string{},
				}
				store.EXPECT().ListServiceAccounts(gomock.Any(), param).Times(1).Return([]*db.Account{&account}, nil)
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK",
			req: &apiv1.QueryParameter{
				PageId:   1,
				PageSize: 5,
			},
			build: func(store *mock.MockStore) {
				account := db.Account{
					ClientID:        clientId,
					NodeAttestation: []string{"AWS_IID"},
				}
				store.EXPECT().ListServiceAccounts(gomock.Any(), param).Times(1).Return([]*db.Account{&account}, nil)
				store.EXPECT().GetInstanceIdentityDocument(gomock.Any(), clientId).Times(1).Return(&db.AwsAttestation{}, nil)
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "DB_ERROR_LIST_SERVICE_ACCOUNT",
			req: &apiv1.QueryParameter{
				PageId:   1,
				PageSize: 5,
			},
			build: func(store *mock.MockStore) {
				store.EXPECT().ListServiceAccounts(gomock.Any(), param).Times(1).Return(nil, fmt.Errorf("list service account error"))
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.EqualError(t, err, "rpc error: code = Internal desc = internal server error")
			},
		},
		{
			name: "DB_ERROR_GET_INSTANCE_IDENTITY_DOCUMENT",
			req: &apiv1.QueryParameter{
				PageId:   1,
				PageSize: 5,
			},
			build: func(store *mock.MockStore) {
				account := db.Account{
					ClientID:        clientId,
					NodeAttestation: []string{"AWS_IID"},
				}
				store.EXPECT().ListServiceAccounts(gomock.Any(), param).Times(1).Return([]*db.Account{&account}, nil)
				store.EXPECT().GetInstanceIdentityDocument(gomock.Any(), clientId).Times(1).Return(nil, fmt.Errorf("get instance identity document error"))
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.Error(t, err)
				require.Empty(t, res)
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

			res, err := c.ListServiceAccounts(context.Background(), tc.req)
			tc.check(t, res, err)
		})
	}
}

func TestGetServiceAccount(t *testing.T) {
	clientId, err := uuid.NewRandom()
	require.NoError(t, err)

	cases := []struct {
		name  string
		req   *apiv1.ServiceAccountId
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.ServiceAccount, err error)
	}{
		{
			name: "OK_NO_ATTESTATION",
			req: &apiv1.ServiceAccountId{
				Uuid: clientId.String(),
			},
			build: func(store *mock.MockStore) {
				store.EXPECT().GetServiceUUID(gomock.Any(), clientId).Times(1).Return(&db.Account{}, nil)
			},
			check: func(t *testing.T, res *apiv1.ServiceAccount, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK",
			req: &apiv1.ServiceAccountId{
				Uuid: clientId.String(),
			},
			build: func(store *mock.MockStore) {
				account := db.Account{
					ClientID:        clientId,
					NodeAttestation: []string{"AWS_IID"},
				}

				store.EXPECT().GetServiceUUID(gomock.Any(), clientId).Times(1).Return(&account, nil)
				store.EXPECT().GetInstanceIdentityDocument(gomock.Any(), clientId).Times(1).Return(&db.AwsAttestation{}, nil)
			},
			check: func(t *testing.T, res *apiv1.ServiceAccount, err error) {
				require.NoError(t, err)
				require.NotEmpty(t, res)
			},
		},
		{
			name: "DB_ERROR_GET_SERVICE_UUID",
			req: &apiv1.ServiceAccountId{
				Uuid: clientId.String(),
			},
			build: func(store *mock.MockStore) {
				store.EXPECT().GetServiceUUID(gomock.Any(), clientId).Times(1).Return(nil, fmt.Errorf("get service uuid error"))
			},
			check: func(t *testing.T, res *apiv1.ServiceAccount, err error) {
				require.Error(t, err)
				require.EqualError(t, err, "rpc error: code = Internal desc = internal server error")
				require.Empty(t, res)
			},
		},
		{
			name: "DB_ERROR_GET_INSTANCE_IDENTITY_DOCUMENT",
			req: &apiv1.ServiceAccountId{
				Uuid: clientId.String(),
			},
			build: func(store *mock.MockStore) {
				account := db.Account{
					ClientID:        clientId,
					NodeAttestation: []string{"AWS_IID"},
				}
				store.EXPECT().GetServiceUUID(gomock.Any(), clientId).Times(1).Return(&account, nil)
				store.EXPECT().GetInstanceIdentityDocument(gomock.Any(), clientId).Times(1).Return(nil, fmt.Errorf("get instance identity document"))
			},
			check: func(t *testing.T, res *apiv1.ServiceAccount, err error) {
				require.Error(t, err)
				require.EqualError(t, err, "rpc error: code = Internal desc = internal server error")
				require.Empty(t, res)
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

			res, err := c.GetServiceAccountUuid(context.Background(), tc.req)
			tc.check(t, res, err)
		})
	}
}

func TestGetServiceAccountByName(t *testing.T) {
	account_name := "example"
	request := &apiv1.ServiceAccountName{
		ServiceAccount: account_name,
	}
	clientId, err := uuid.NewRandom()
	require.NoError(t, err)

	cases := []struct {
		name  string
		req   *apiv1.ServiceAccountName
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.ServiceAccounts, err error)
	}{
		{
			name: "OK_NO_SERVICE_ACCOUNT",
			req:  request,
			build: func(store *mock.MockStore) {
				store.EXPECT().GetServiceAccounts(gomock.Any(), account_name).Times(1).Return([]*db.Account{}, nil)
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK_NO_ATTESTATION",
			req:  request,
			build: func(store *mock.MockStore) {
				account := db.Account{
					ServiceAccount: account_name,
					ClientID:       clientId,
				}
				store.EXPECT().GetServiceAccounts(gomock.Any(), account_name).Times(1).Return([]*db.Account{&account}, nil)
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK",
			req:  request,
			build: func(store *mock.MockStore) {
				account := db.Account{
					ServiceAccount:  account_name,
					ClientID:        clientId,
					NodeAttestation: []string{"AWS_IID"},
				}
				store.EXPECT().GetServiceAccounts(gomock.Any(), account_name).Times(1).Return([]*db.Account{&account}, nil)
				store.EXPECT().GetInstanceIdentityDocument(gomock.Any(), clientId).Times(1).Return(&db.AwsAttestation{}, nil)
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "DB_ERROR_GET_SERVICE_ACCOUNTS",
			req:  request,
			build: func(store *mock.MockStore) {
				store.EXPECT().GetServiceAccounts(gomock.Any(), account_name).Times(1).Return(nil, fmt.Errorf("get service accounts error"))
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
				require.Error(t, err)
				require.EqualError(t, err, "rpc error: code = Internal desc = internal server error")
				require.Empty(t, res)
			},
		},
		{
			name: "DB_ERROR_GET_INSTANCE_IDENTITY_DOCUMENT",
			req:  request,
			build: func(store *mock.MockStore) {
				account := db.Account{
					ServiceAccount:  account_name,
					ClientID:        clientId,
					NodeAttestation: []string{"AWS_IID"},
				}
				store.EXPECT().GetServiceAccounts(gomock.Any(), account_name).Times(1).Return([]*db.Account{&account}, nil)
				store.EXPECT().GetInstanceIdentityDocument(gomock.Any(), clientId).Times(1).Return(nil, fmt.Errorf("get instance identity document err"))
			},
			check: func(t *testing.T, res *apiv1.ServiceAccounts, err error) {
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

			res, err := c.GetServiceAccountName(context.Background(), tc.req)
			tc.check(t, res, err)
		})
	}
}
