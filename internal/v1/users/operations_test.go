package users

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	lib "github.com/coinbase/baseca/internal/lib/authentication"
	"github.com/coinbase/baseca/internal/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestCreateUser(t *testing.T) {
	user, user_credentials := GenerateTestUser(t, types.READ.String(), 20)

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
	user, user_credentials := GenerateTestUser(t, types.READ.String(), 20)

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

func GenerateTestUser(t *testing.T, permissions string, length int) (db.User, string) {
	client_id, _ := uuid.NewRandom()
	credentials := generateRandomCredentials(length)
	hashed_credentials, _ := lib.HashPassword(credentials)
	email := generateRandomEmail()
	username := generateRandomUsername()
	full_name := generateRandomName()

	return db.User{
		Uuid:                client_id,
		Username:            username,
		HashedCredential:    hashed_credentials,
		FullName:            full_name,
		Email:               email,
		Permissions:         permissions,
		CredentialChangedAt: time.Now().UTC(),
		CreatedAt:           time.Now().UTC(),
	}, credentials
}

func generateRandomEmail() string {
	randBytes := make([]byte, 8)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}

	// Encode the random bytes using base64 encoding to get an ASCII string
	randStr := base64.URLEncoding.EncodeToString(randBytes)

	// Use the first 10 characters of the base64-encoded string as the email username
	return fmt.Sprintf("%s@coinbase.com", randStr[:10])
}

func generateRandomName() string {
	// Generate random bytes for the first and last name
	firstNameBytes := make([]byte, 6)
	_, err := rand.Read(firstNameBytes)
	if err != nil {
		panic(err)
	}
	lastNameBytes := make([]byte, 6)
	_, err = rand.Read(lastNameBytes)
	if err != nil {
		panic(err)
	}

	// Convert the random bytes to hexadecimal strings
	firstNameHex := hex.EncodeToString(firstNameBytes)[:10]
	lastNameHex := hex.EncodeToString(lastNameBytes)[:10]

	return fmt.Sprintf("%s %s", firstNameHex, lastNameHex)
}

func generateRandomUsername() string {
	// Generate random bytes for the username
	usernameBytes := make([]byte, 8)
	_, err := rand.Read(usernameBytes)
	if err != nil {
		panic(err)
	}

	// Encode the random bytes using base64 encoding to get an ASCII string
	usernameStr := base64.URLEncoding.EncodeToString(usernameBytes)

	// Use the first 10 characters of the base64-encoded string as the username
	return usernameStr[:10]
}

func generateRandomCredentials(length int) string {
	// Generate random bytes for the credentials
	credentialsBytes := make([]byte, length)
	_, err := rand.Read(credentialsBytes)
	if err != nil {
		panic(err)
	}

	// Encode the random bytes using base64 encoding to get an ASCII string
	credentialsStr := base64.URLEncoding.EncodeToString(credentialsBytes)

	// Return the first `length` characters of the base64-encoded string
	return credentialsStr[:length]
}
