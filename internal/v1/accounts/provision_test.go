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
	lib "github.com/coinbase/baseca/internal/lib/authentication"
	"github.com/coinbase/baseca/internal/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestCreateProvisionerAccount(t *testing.T) {
	id, err := uuid.NewRandom()
	require.NoError(t, err)

	authClaim := &lib.Claims{
		Permission: "ADMIN",
		Subject:    id,
		IssuedAt:   time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().AddDate(0, 0, 1),
		NotBefore:  time.Now().UTC(),
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
			ctx:  context.WithValue(context.Background(), types.UserAuthenticationContextKey, authClaim),
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
			ctx:  context.WithValue(context.Background(), types.UserAuthenticationContextKey, authClaim),
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

func TestProvisionServiceAccount(t *testing.T) {
	region := "us-east-1"
	id, err := uuid.NewRandom()
	require.NoError(t, err)

	authClaim := &types.ProvisionerAccountPayload{
		ClientId:                   id,
		ProvisionerAccount:         "provisioner",
		Environments:               []string{"sandbox"},
		ValidSubjectAlternateNames: []string{"*.example.com"},
		MaxCertificateValidity:     uint32(30),
		ExtendedKeys:               []string{"EndEntityServerAuthCertificate"},
		RegularExpression:          "^.{0,250}$",
	}

	cases := []struct {
		name  string
		req   *apiv1.ProvisionServiceAccountRequest
		ctx   context.Context
		build func(store *mock.MockStore)
		check func(t *testing.T, res *apiv1.ProvisionServiceAccountResponse, err error)
	}{
		{
			name: "OK_NO_ATTESTATION",
			req: &apiv1.ProvisionServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"sandbox.example.com"},
				CertificateAuthorities:  []string{"sandbox_use1"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				ExtendedKey:             "EndEntityServerAuthCertificate",
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
					CreatedBy:                   authClaim.ClientId,
					NodeAttestation:             []string{},
					Provisioned:                 true,
				}
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
				store.EXPECT().CreateServiceAccount(
					gomock.Any(),
					EqProvisionServiceAccountParams(account_arg),
				).Times(1).Return(&db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.ProvisionerAuthenticationContextKey, authClaim),
			check: func(t *testing.T, res *apiv1.ProvisionServiceAccountResponse, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK_DEFAULT_CERTIFICATE_AUTHORITIES",
			req: &apiv1.ProvisionServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"sandbox.example.com"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				ExtendedKey:             "EndEntityServerAuthCertificate",
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
					ValidCertificateAuthorities: []string{"sandbox_use1", "sandbox_use2"},
					SubordinateCa:               "infrastructure",
					Team:                        "Infrastructure Security",
					Email:                       "security@coinbase.com",
					CreatedBy:                   authClaim.ClientId,
					NodeAttestation:             []string{},
					Provisioned:                 true,
				}
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
				store.EXPECT().CreateServiceAccount(
					gomock.Any(),
					EqProvisionServiceAccountParams(account_arg),
				).Times(1).Return(&db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.ProvisionerAuthenticationContextKey, authClaim),
			check: func(t *testing.T, res *apiv1.ProvisionServiceAccountResponse, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "OK_REGION_REQUIRED_AND_VALID_CA",
			req: &apiv1.ProvisionServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"sandbox.example.com"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				Region:                  &region,
				ExtendedKey:             "EndEntityServerAuthCertificate",
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
					CreatedBy:                   authClaim.ClientId,
					NodeAttestation:             []string{},
					Provisioned:                 true,
				}

				arg := db.ListValidCertificateAuthorityFromSubordinateCAParams{
					SubordinateCa: "infrastructure",
					Environment:   "sandbox",
				}
				store.EXPECT().ListValidCertificateAuthorityFromSubordinateCA(gomock.Any(), arg).Times(1).Return([]any{"sandbox_use1"}, nil)
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
				store.EXPECT().CreateServiceAccount(
					gomock.Any(),
					EqProvisionServiceAccountParams(account_arg),
				).Times(1).Return(&db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.ProvisionerAuthenticationContextKey, authClaim),
			check: func(t *testing.T, res *apiv1.ProvisionServiceAccountResponse, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "ERROR_REGION_REQUIRED_AND_CA_WITH_CONFLICTING_REGION",
			req: &apiv1.ProvisionServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"sandbox.example.com"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				Region:                  &region,
				ExtendedKey:             "EndEntityServerAuthCertificate",
				Team:                    "Infrastructure Security",
				Email:                   "security@coinbase.com",
			},
			build: func(store *mock.MockStore) {
				arg := db.ListValidCertificateAuthorityFromSubordinateCAParams{
					SubordinateCa: "infrastructure",
					Environment:   "sandbox",
				}
				store.EXPECT().ListValidCertificateAuthorityFromSubordinateCA(gomock.Any(), arg).Times(1).Return([]any{"sandbox_use2"}, nil)
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.ProvisionerAuthenticationContextKey, authClaim),
			check: func(t *testing.T, res *apiv1.ProvisionServiceAccountResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.EqualError(t, err, "rpc error: code = InvalidArgument desc = subordinate ca does not support region")
			},
		},
		{
			name: "ERROR_REGION_REQUIRED_AND_CA_WITH_MULTIPLE_REGIONS",
			req: &apiv1.ProvisionServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"sandbox.example.com"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				Region:                  &region,
				ExtendedKey:             "EndEntityServerAuthCertificate",
				Team:                    "Infrastructure Security",
				Email:                   "security@coinbase.com",
			},
			build: func(store *mock.MockStore) {
				arg := db.ListValidCertificateAuthorityFromSubordinateCAParams{
					SubordinateCa: "infrastructure",
					Environment:   "sandbox",
				}
				store.EXPECT().ListValidCertificateAuthorityFromSubordinateCA(gomock.Any(), arg).Times(1).Return([]any{"sandbox_use2", "sandbox_use1"}, nil)
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.ProvisionerAuthenticationContextKey, authClaim),
			check: func(t *testing.T, res *apiv1.ProvisionServiceAccountResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.EqualError(t, err, "rpc error: code = InvalidArgument desc = subordinate ca does not support region")
			},
		},
		{
			name: "ERROR_CERTIFICATE_AUTHORITY_DIFFERENT_REGION",
			req: &apiv1.ProvisionServiceAccountRequest{
				ServiceAccount:          "example",
				Environment:             "sandbox",
				SubjectAlternativeNames: []string{"sandbox.example.com"},
				SubordinateCa:           "infrastructure",
				CertificateValidity:     30,
				Region:                  &region,
				CertificateAuthorities:  []string{"sandbox_use2"}, // Different Region than Region Field (us-east-1)
				ExtendedKey:             "EndEntityServerAuthCertificate",
				Team:                    "Infrastructure Security",
				Email:                   "security@coinbase.com",
			},
			build: func(store *mock.MockStore) {
				arg := db.ListValidCertificateAuthorityFromSubordinateCAParams{
					SubordinateCa: "infrastructure",
					Environment:   "sandbox",
				}
				store.EXPECT().ListValidCertificateAuthorityFromSubordinateCA(gomock.Any(), arg).Times(1).Return([]any{"sandbox_use2", "sandbox_use1"}, nil)
				store.EXPECT().ListServiceAccounts(gomock.Any(), gomock.Any()).Times(1).Return([]*db.Account{}, nil)
			},
			ctx: context.WithValue(context.Background(), types.ProvisionerAuthenticationContextKey, authClaim),
			check: func(t *testing.T, res *apiv1.ProvisionServiceAccountResponse, err error) {
				require.Error(t, err)
				require.Empty(t, res)
				require.EqualError(t, err, "rpc error: code = InvalidArgument desc = subordinate ca does not support region")
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

			res, err := c.ProvisionServiceAccount(tc.ctx, tc.req)
			tc.check(t, res, err)
		})
	}
}

type eqCreateProvisionerProvisionerParamsMatcher struct {
	arg      db.CreateProvisionerAccountParams
	password string
}

func (e eqCreateProvisionerProvisionerParamsMatcher) Matches(x any) bool {
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

type eqProvisionServiceAccountParams struct {
	arg db.CreateServiceAccountParams
}

func EqProvisionServiceAccountParams(arg db.CreateServiceAccountParams) gomock.Matcher {
	return eqProvisionServiceAccountParams{arg}
}

func (e eqProvisionServiceAccountParams) Matches(x any) bool {
	arg, ok := x.(db.CreateServiceAccountParams)
	if !ok {
		return false
	}

	e.arg.ClientID = arg.ClientID
	e.arg.ApiToken = arg.ApiToken
	e.arg.CreatedAt = arg.CreatedAt

	return reflect.DeepEqual(e.arg, arg)
}

func (e eqProvisionServiceAccountParams) String() string {
	return fmt.Sprintf("%v", e.arg)
}
