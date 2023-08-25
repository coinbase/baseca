package accounts

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/authentication"
	"github.com/coinbase/baseca/internal/types"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCreateProvisionerAccount(t *testing.T) {
	id, err := uuid.NewRandom()
	require.NoError(t, err)

	authClaim := &authentication.Claims{
		Permission: "ADMIN",
		Subject:    id,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().AddDate(0, 0, 1),
		NotBefore:  time.Now(),
	}

	attestation := apiv1.AWSInstanceIdentityDocument{
		RoleArn:        "arn:aws:iam::123456789012:instance-profile/role",
		AssumeRole:     "arn:aws:iam::123456789012:role/assumed-role",
		SecurityGroups: []string{"sg-0123456789abcdef0"},
		Region:         "us-east-1",
	}

	request := &apiv1.CreateProvisionerAccountRequest{
		ProvisionerAccount:      "example",
		Environments:            []string{"development"},
		SubjectAlternativeNames: []string{"development.example.com"},
		ExtendedKeys:            []string{"EndEntityServerAuthCertificate"},
		MaxCertificateValidity:  30,
		Team:                    "Team",
		Email:                   "example@coinbase.com",
	}

	requestOK := &apiv1.CreateProvisionerAccountRequest{
		ProvisionerAccount:      "example",
		Environments:            []string{"development"},
		SubjectAlternativeNames: []string{"development.example.com"},
		ExtendedKeys:            []string{"EndEntityServerAuthCertificate"},
		MaxCertificateValidity:  30,
		NodeAttestation: &apiv1.NodeAttestation{
			AwsIid: &attestation,
		},
		Team:  "Team",
		Email: "example@coinbase.com",
	}

	cases := []struct {
		name  string
		req   *apiv1.CreateProvisionerAccountRequest
		ctx   context.Context
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.CreateProvisionerAccountResponse, err error)
	}{
		{
			name: "OK_NO_ATTESTATION",
			req:  request,
			ctx:  context.WithValue(context.Background(), types.AuthorizationPayloadKey, authClaim),
			build: func(store *mock.MockStore) {
				account_arg := db.CreateProvisionerAccountParams{
					ProvisionerAccount:         "example",
					Environments:               []string{"development"},
					ValidSubjectAlternateNames: []string{"development.example.com"},
					ExtendedKeys:               []string{"EndEntityServerAuthCertificate"},
					MaxCertificateValidity:     30,
					Team:                       "Team",
					Email:                      "example@coinbase.com",
					CreatedBy:                  authClaim.Subject,
					NodeAttestation:            []string{},
				}
				store.EXPECT().ListProvisionerAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Provisioner{}, nil)
				store.EXPECT().CreateProvisionerAccount(gomock.Any(),
					EqCreateProvisionerAccountParams(account_arg, "provisioner arg matcher")).Times(1).Return(&db.Provisioner{}, nil)
			},
			check: func(t *testing.T, res *apiv1.CreateProvisionerAccountResponse, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK",
			req:  requestOK,
			ctx:  context.WithValue(context.Background(), types.AuthorizationPayloadKey, authClaim),
			build: func(store *mock.MockStore) {
				account_arg := db.CreateProvisionerAccountParams{
					ProvisionerAccount:         "example",
					Environments:               []string{"development"},
					ValidSubjectAlternateNames: []string{"development.example.com"},
					ExtendedKeys:               []string{"EndEntityServerAuthCertificate"},
					MaxCertificateValidity:     30,
					Team:                       "Team",
					Email:                      "example@coinbase.com",
					CreatedBy:                  authClaim.Subject,
					NodeAttestation:            []string{"AWS_IID"},
				}

				attestation_arg := db.StoreInstanceIdentityDocumentParams{
					RoleArn:         sql.NullString{String: attestation.RoleArn, Valid: true},
					AssumeRole:      sql.NullString{String: attestation.AssumeRole, Valid: true},
					SecurityGroupID: attestation.SecurityGroups,
					Region:          sql.NullString{String: attestation.Region, Valid: true},
				}

				store.EXPECT().ListProvisionerAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Provisioner{}, nil)
				store.EXPECT().TxCreateProvisionerAccount(gomock.Any(),
					EqCreateProvisionerAccountParams(account_arg, "provisioner arg matcher"),
					EqStoreInstanceIdentityDocumentParams(attestation_arg, "iid arg matcher"),
				).Times(1).Return(&db.Provisioner{}, nil)
			},
			check: func(t *testing.T, res *apiv1.CreateProvisionerAccountResponse, err error) {
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

			c, err := buildAccountsConfig(store)
			require.NoError(t, err)

			res, err := c.CreateProvisionerAccount(tc.ctx, tc.req)
			tc.check(t, res, err)
		})
	}
}

type eqCreateProvisionerProvisionerParamsMatcher struct {
	arg      db.CreateProvisionerAccountParams
	password string
}

func (e eqCreateProvisionerProvisionerParamsMatcher) Matches(x interface{}) bool {
	arg, ok := x.(db.CreateProvisionerAccountParams)
	if !ok {
		return false
	}

	e.arg.ClientID = arg.ClientID
	e.arg.ApiToken = arg.ApiToken
	e.arg.CreatedAt = arg.CreatedAt
	return reflect.DeepEqual(e.arg, arg)
}

func (e eqCreateProvisionerProvisionerParamsMatcher) String() string {
	return fmt.Sprintf("%v", e.arg)
}

func EqCreateProvisionerAccountParams(arg db.CreateProvisionerAccountParams, password string) gomock.Matcher {
	return eqCreateProvisionerProvisionerParamsMatcher{arg, password}
}
