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

func TestCreateServiceAccount(t *testing.T) {
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

	accountParam := db.CreateServiceAccountParams{
		ServiceAccount:              "example",
		Environment:                 "sandbox",
		ValidSubjectAlternateName:   []string{"sandbox.example.com"},
		ExtendedKey:                 "EndEntityServerAuthCertificate",
		NodeAttestation:             []string{"AWS_IID"},
		CertificateValidity:         30,
		ValidCertificateAuthorities: []string{"sandbox_use1"},
		SubordinateCa:               "infrastructure",
		Provisioned:                 false,
		Team:                        "Infrastructure Security",
		Email:                       "security@coinbase.com",
		CreatedBy:                   id,
	}

	attestationParam := db.StoreInstanceIdentityDocumentParams{
		RoleArn:         sql.NullString{String: attestation.RoleArn, Valid: true},
		AssumeRole:      sql.NullString{String: attestation.AssumeRole, Valid: true},
		SecurityGroupID: attestation.SecurityGroups,
		Region:          sql.NullString{String: attestation.Region, Valid: true},
	}

	request := apiv1.CreateServiceAccountRequest{
		ServiceAccount:          "example",
		Environment:             "sandbox",
		SubjectAlternativeNames: []string{"sandbox.example.com"},
		ExtendedKey:             "EndEntityServerAuthCertificate",
		NodeAttestation: &apiv1.NodeAttestation{
			AwsIid: &attestation,
		},
		CertificateAuthorities: []string{"sandbox_use1"},
		SubordinateCa:          "infrastructure",
		CertificateValidity:    30,
		Team:                   "Infrastructure Security",
		Email:                  "security@coinbase.com",
	}

	cases := []struct {
		name  string
		req   *apiv1.CreateServiceAccountRequest
		build func(store *mock.MockStore)
		ctx   context.Context
		check func(t *testing.T, res *apiv1.CreateServiceAccountResponse, err error)
	}{
		{
			name: "OK",
			req:  &request,
			build: func(store *mock.MockStore) {
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
				store.EXPECT().TxCreateServiceAccount(
					gomock.Any(),
					EqCreateServiceAccountParams(accountParam, "account arg matcher"),
					EqStoreInstanceIdentityDocumentParams(attestationParam, "iid arg matcher"),
				).Times(1).Return(&db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.AuthorizationPayloadKey, authClaim),
			check: func(t *testing.T, res *apiv1.CreateServiceAccountResponse, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK_NO_ATTESTATION",
			req: &apiv1.CreateServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"sandbox.example.com"},
				ExtendedKey:             "EndEntityServerAuthCertificate",
				CertificateAuthorities:  []string{"sandbox_use1"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				Team:                    "Infrastructure Security",
				Email:                   "security@coinbase.com",
			},
			build: func(store *mock.MockStore) {
				account_arg := db.CreateServiceAccountParams{
					ServiceAccount:              "example",
					Environment:                 "sandbox",
					ValidSubjectAlternateName:   []string{"sandbox.example.com"},
					ExtendedKey:                 "EndEntityServerAuthCertificate",
					CertificateValidity:         30,
					ValidCertificateAuthorities: []string{"sandbox_use1"},
					SubordinateCa:               "infrastructure",
					Team:                        "Infrastructure Security",
					Email:                       "security@coinbase.com",
					CreatedBy:                   authClaim.Subject,
					NodeAttestation:             []string{},
				}
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
				store.EXPECT().CreateServiceAccount(
					gomock.Any(),
					EqCreateServiceAccountParams(account_arg, "account arg matcher"),
				).Times(1).Return(&db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.AuthorizationPayloadKey, authClaim),
			check: func(t *testing.T, res *apiv1.CreateServiceAccountResponse, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK_WILDCARD",
			req: &apiv1.CreateServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"*.example.com"},
				ExtendedKey:             "EndEntityServerAuthCertificate",
				CertificateAuthorities:  []string{"sandbox_use1"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				Team:                    "Infrastructure Security",
				Email:                   "security@coinbase.com",
			},
			build: func(store *mock.MockStore) {
				account_arg := db.CreateServiceAccountParams{
					ServiceAccount:              "example",
					Environment:                 "sandbox",
					ValidSubjectAlternateName:   []string{"*.example.com"},
					ExtendedKey:                 "EndEntityServerAuthCertificate",
					CertificateValidity:         30,
					ValidCertificateAuthorities: []string{"sandbox_use1"},
					SubordinateCa:               "infrastructure",
					Team:                        "Infrastructure Security",
					Email:                       "security@coinbase.com",
					CreatedBy:                   authClaim.Subject,
					NodeAttestation:             []string{},
				}
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
				store.EXPECT().CreateServiceAccount(
					gomock.Any(),
					EqCreateServiceAccountParams(account_arg, "account arg matcher"),
				).Times(1).Return(&db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.AuthorizationPayloadKey, authClaim),
			check: func(t *testing.T, res *apiv1.CreateServiceAccountResponse, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "ERROR_INVALID_SUBJECT_ALTERNATIVE_NAME",
			req: &apiv1.CreateServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"000.example.com"},
				ExtendedKey:             "EndEntityServerAuthCertificate",
				CertificateAuthorities:  []string{"sandbox_use1"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				Team:                    "Infrastructure Security",
				Email:                   "security@coinbase.com",
			},
			build: func(store *mock.MockStore) {},
			ctx:   context.WithValue(context.Background(), types.AuthorizationPayloadKey, authClaim),
			check: func(t *testing.T, res *apiv1.CreateServiceAccountResponse, err error) {
				require.Error(t, err)
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

			res, err := c.CreateServiceAccount(tc.ctx, tc.req)
			tc.check(t, res, err)
		})
	}
}

type eqCreateServiceAccountParamsMatcher struct {
	arg      db.CreateServiceAccountParams
	password string
}

func (e eqCreateServiceAccountParamsMatcher) Matches(x interface{}) bool {
	arg, ok := x.(db.CreateServiceAccountParams)
	if !ok {
		return false
	}

	e.arg.ClientID = arg.ClientID
	e.arg.ApiToken = arg.ApiToken
	e.arg.CreatedAt = arg.CreatedAt
	return reflect.DeepEqual(e.arg, arg)
}

func (e eqCreateServiceAccountParamsMatcher) String() string {
	return fmt.Sprintf("%v", e.arg)
}

func EqCreateServiceAccountParams(arg db.CreateServiceAccountParams, password string) gomock.Matcher {
	return eqCreateServiceAccountParamsMatcher{arg, password}
}

type eqStoreInstanceIdentityDocumentParamsMatcher struct {
	arg      db.StoreInstanceIdentityDocumentParams
	password string
}

func (e eqStoreInstanceIdentityDocumentParamsMatcher) Matches(x interface{}) bool {
	arg, ok := x.(db.StoreInstanceIdentityDocumentParams)
	if !ok {
		return false
	}

	e.arg.ClientID = arg.ClientID
	e.arg.InstanceID = arg.InstanceID
	e.arg.ImageID = arg.ImageID
	e.arg.InstanceTags = arg.InstanceTags
	return reflect.DeepEqual(e.arg, arg)
}

func (e eqStoreInstanceIdentityDocumentParamsMatcher) String() string {
	return fmt.Sprintf("%v", e.arg)
}

func EqStoreInstanceIdentityDocumentParams(arg db.StoreInstanceIdentityDocumentParams, password string) gomock.Matcher {
	return eqStoreInstanceIdentityDocumentParamsMatcher{arg, password}
}
