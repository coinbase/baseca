// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.21.0

package db

import (
	"context"

	"github.com/google/uuid"
)

type Querier interface {
	CreateProvisionerAccount(ctx context.Context, arg CreateProvisionerAccountParams) (*Provisioner, error)
	CreateServiceAccount(ctx context.Context, arg CreateServiceAccountParams) (*Account, error)
	CreateUser(ctx context.Context, arg CreateUserParams) (*User, error)
	DeleteInstanceIdentityDocument(ctx context.Context, clientID uuid.UUID) error
	DeleteProvisionerAccount(ctx context.Context, clientID uuid.UUID) error
	DeleteServiceAccount(ctx context.Context, clientID uuid.UUID) error
	DeleteUser(ctx context.Context, username string) error
	GetCertificate(ctx context.Context, serialNumber string) (*Certificate, error)
	GetInstanceIdentityDocument(ctx context.Context, clientID uuid.UUID) (*AwsAttestation, error)
	GetProvisionerUUID(ctx context.Context, clientID uuid.UUID) (*Provisioner, error)
	GetServiceAccountByMetadata(ctx context.Context, arg GetServiceAccountByMetadataParams) ([]*Account, error)
	GetServiceAccountBySAN(ctx context.Context, dollar_1 []string) ([]*Account, error)
	GetServiceAccounts(ctx context.Context, serviceAccount string) ([]*Account, error)
	GetServiceUUID(ctx context.Context, clientID uuid.UUID) (*Account, error)
	GetSignedCertificateByMetadata(ctx context.Context, arg GetSignedCertificateByMetadataParams) ([]*Certificate, error)
	GetUser(ctx context.Context, username string) (*User, error)
	ListCertificateSubjectAlternativeName(ctx context.Context, arg ListCertificateSubjectAlternativeNameParams) ([]*Certificate, error)
	ListCertificates(ctx context.Context, arg ListCertificatesParams) ([]*Certificate, error)
	ListProvisionerAccounts(ctx context.Context, arg ListProvisionerAccountsParams) ([]*Provisioner, error)
	ListServiceAccounts(ctx context.Context, arg ListServiceAccountsParams) ([]*Account, error)
	ListUsers(ctx context.Context, arg ListUsersParams) ([]*User, error)
	ListValidCertificateAuthorityFromSubordinateCA(ctx context.Context, arg ListValidCertificateAuthorityFromSubordinateCAParams) ([]interface{}, error)
	LogCertificate(ctx context.Context, arg LogCertificateParams) (*Certificate, error)
	RevokeIssuedCertificateSerialNumber(ctx context.Context, arg RevokeIssuedCertificateSerialNumberParams) error
	StoreInstanceIdentityDocument(ctx context.Context, arg StoreInstanceIdentityDocumentParams) (*AwsAttestation, error)
	UpdateInstanceIdentityNodeAttestor(ctx context.Context, arg UpdateInstanceIdentityNodeAttestorParams) (*Account, error)
	UpdateServiceAccount(ctx context.Context, arg UpdateServiceAccountParams) (*Account, error)
	UpdateUserAuthentication(ctx context.Context, arg UpdateUserAuthenticationParams) (*User, error)
	UpdateUserPermission(ctx context.Context, arg UpdateUserPermissionParams) (*User, error)
}

var _ Querier = (*Queries)(nil)
