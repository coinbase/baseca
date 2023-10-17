package users

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"

	"github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	lib "github.com/coinbase/baseca/internal/lib/authentication"
	"github.com/coinbase/baseca/internal/lib/util"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	_read = "READ"
)

func TestCreateUser(t *testing.T) {
	user, user_credentials := util.GenerateTestUser(t, _read, 20)

	cases := []struct {
		name  string
		req   *apiv1.CreateUserRequest
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.User, err error)
	}{
		{
			name: "OK",
			req: &apiv1.CreateUserRequest{
				Username:    user.Username,
				Password:    user_credentials,
				FullName:    user.FullName,
				Email:       user.Email,
				Permissions: user.Permissions,
			},
			build: func(store *mock.MockStore) {
				arg := db.CreateUserParams{
					Uuid:        user.Uuid,
					Username:    user.Username,
					FullName:    user.FullName,
					Email:       user.Email,
					Permissions: user.Permissions,
				}
				store.EXPECT().GetUser(gomock.Any(), arg.Username).Times(1).Return(nil, sql.ErrNoRows)
				store.EXPECT().CreateUser(gomock.Any(), EqCreateUserParams(arg, user_credentials)).Times(1).Return(&user, nil)
			},
			check: func(t *testing.T, res *apiv1.User, err error) {
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

			user, err := buildUsersConfig(store)
			require.NoError(t, err)

			res, err := user.CreateUser(context.Background(), tc.req)
			tc.check(t, res, err)
		})
	}
}

func TestLoginUser(t *testing.T) {
	user, user_credentials := util.GenerateTestUser(t, _read, 20)

	cases := []struct {
		name  string
		req   *apiv1.LoginUserRequest
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.LoginUserResponse, err error)
	}{
		{
			name: "OK",
			req: &apiv1.LoginUserRequest{
				Username: user.Username,
				Password: user_credentials,
			},
			build: func(store *mock.MockStore) {
				store.EXPECT().GetUser(gomock.Any(), user.Username).Times(1).Return(&user, nil)
			},
			check: func(t *testing.T, res *apiv1.LoginUserResponse, err error) {
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

			user, err := buildUsersConfig(store)
			require.NoError(t, err)

			res, err := user.LoginUser(context.Background(), tc.req)
			tc.check(t, res, err)
		})
	}
}

type eqCreateUserParamsMatcher struct {
	arg      db.CreateUserParams
	password string
}

func (e eqCreateUserParamsMatcher) Matches(x any) bool {
	arg, ok := x.(db.CreateUserParams)
	if !ok {
		return false
	}

	err := lib.CheckPassword(e.password, arg.HashedCredential)
	if err != nil {
		return false
	}

	e.arg.Uuid = arg.Uuid
	e.arg.HashedCredential = arg.HashedCredential
	return reflect.DeepEqual(e.arg, arg)
}

func (e eqCreateUserParamsMatcher) String() string {
	return fmt.Sprintf("%v", e.arg)
}

func EqCreateUserParams(arg db.CreateUserParams, password string) gomock.Matcher {
	return eqCreateUserParamsMatcher{arg, password}
}
