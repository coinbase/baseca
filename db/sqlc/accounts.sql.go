// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: accounts.sql

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const createServiceAccount = `-- name: CreateServiceAccount :one
INSERT INTO accounts (
    client_id,
    api_token,
    service_account,
    environment,
    team,
    email,
    regular_expression,
    valid_subject_alternate_name,
    valid_certificate_authorities,
    extended_key,
    certificate_validity,
    subordinate_ca,
    node_attestation,
    created_at,
    created_by
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
) RETURNING client_id, api_token, service_account, environment, team, email, regular_expression, valid_subject_alternate_name, valid_certificate_authorities, extended_key, certificate_validity, subordinate_ca, node_attestation, created_at, created_by
`

type CreateServiceAccountParams struct {
	ClientID                    uuid.UUID      `json:"client_id"`
	ApiToken                    string         `json:"api_token"`
	ServiceAccount              string         `json:"service_account"`
	Environment                 string         `json:"environment"`
	Team                        string         `json:"team"`
	Email                       string         `json:"email"`
	RegularExpression           sql.NullString `json:"regular_expression"`
	ValidSubjectAlternateName   []string       `json:"valid_subject_alternate_name"`
	ValidCertificateAuthorities []string       `json:"valid_certificate_authorities"`
	ExtendedKey                 string         `json:"extended_key"`
	CertificateValidity         int16          `json:"certificate_validity"`
	SubordinateCa               string         `json:"subordinate_ca"`
	NodeAttestation             []string       `json:"node_attestation"`
	CreatedAt                   time.Time      `json:"created_at"`
	CreatedBy                   uuid.UUID      `json:"created_by"`
}

func (q *Queries) CreateServiceAccount(ctx context.Context, arg CreateServiceAccountParams) (*Account, error) {
	row := q.db.QueryRowContext(ctx, createServiceAccount,
		arg.ClientID,
		arg.ApiToken,
		arg.ServiceAccount,
		arg.Environment,
		arg.Team,
		arg.Email,
		arg.RegularExpression,
		pq.Array(arg.ValidSubjectAlternateName),
		pq.Array(arg.ValidCertificateAuthorities),
		arg.ExtendedKey,
		arg.CertificateValidity,
		arg.SubordinateCa,
		pq.Array(arg.NodeAttestation),
		arg.CreatedAt,
		arg.CreatedBy,
	)
	var i Account
	err := row.Scan(
		&i.ClientID,
		&i.ApiToken,
		&i.ServiceAccount,
		&i.Environment,
		&i.Team,
		&i.Email,
		&i.RegularExpression,
		pq.Array(&i.ValidSubjectAlternateName),
		pq.Array(&i.ValidCertificateAuthorities),
		&i.ExtendedKey,
		&i.CertificateValidity,
		&i.SubordinateCa,
		pq.Array(&i.NodeAttestation),
		&i.CreatedAt,
		&i.CreatedBy,
	)
	return &i, err
}

const deleteServiceAccount = `-- name: DeleteServiceAccount :exec
DELETE FROM accounts 
WHERE client_id = $1
`

func (q *Queries) DeleteServiceAccount(ctx context.Context, clientID uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteServiceAccount, clientID)
	return err
}

const getServiceAccounts = `-- name: GetServiceAccounts :many
SELECT client_id, api_token, service_account, environment, team, email, regular_expression, valid_subject_alternate_name, valid_certificate_authorities, extended_key, certificate_validity, subordinate_ca, node_attestation, created_at, created_by FROM accounts
WHERE service_account = $1
`

func (q *Queries) GetServiceAccounts(ctx context.Context, serviceAccount string) ([]*Account, error) {
	rows, err := q.db.QueryContext(ctx, getServiceAccounts, serviceAccount)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []*Account{}
	for rows.Next() {
		var i Account
		if err := rows.Scan(
			&i.ClientID,
			&i.ApiToken,
			&i.ServiceAccount,
			&i.Environment,
			&i.Team,
			&i.Email,
			&i.RegularExpression,
			pq.Array(&i.ValidSubjectAlternateName),
			pq.Array(&i.ValidCertificateAuthorities),
			&i.ExtendedKey,
			&i.CertificateValidity,
			&i.SubordinateCa,
			pq.Array(&i.NodeAttestation),
			&i.CreatedAt,
			&i.CreatedBy,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getServiceUUID = `-- name: GetServiceUUID :one
SELECT client_id, api_token, service_account, environment, team, email, regular_expression, valid_subject_alternate_name, valid_certificate_authorities, extended_key, certificate_validity, subordinate_ca, node_attestation, created_at, created_by FROM accounts
WHERE client_id = $1
`

func (q *Queries) GetServiceUUID(ctx context.Context, clientID uuid.UUID) (*Account, error) {
	row := q.db.QueryRowContext(ctx, getServiceUUID, clientID)
	var i Account
	err := row.Scan(
		&i.ClientID,
		&i.ApiToken,
		&i.ServiceAccount,
		&i.Environment,
		&i.Team,
		&i.Email,
		&i.RegularExpression,
		pq.Array(&i.ValidSubjectAlternateName),
		pq.Array(&i.ValidCertificateAuthorities),
		&i.ExtendedKey,
		&i.CertificateValidity,
		&i.SubordinateCa,
		pq.Array(&i.NodeAttestation),
		&i.CreatedAt,
		&i.CreatedBy,
	)
	return &i, err
}

const listServiceAccounts = `-- name: ListServiceAccounts :many
SELECT client_id, api_token, service_account, environment, team, email, regular_expression, valid_subject_alternate_name, valid_certificate_authorities, extended_key, certificate_validity, subordinate_ca, node_attestation, created_at, created_by FROM accounts
ORDER BY service_account
LIMIT $1
OFFSET $2
`

type ListServiceAccountsParams struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

func (q *Queries) ListServiceAccounts(ctx context.Context, arg ListServiceAccountsParams) ([]*Account, error) {
	rows, err := q.db.QueryContext(ctx, listServiceAccounts, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []*Account{}
	for rows.Next() {
		var i Account
		if err := rows.Scan(
			&i.ClientID,
			&i.ApiToken,
			&i.ServiceAccount,
			&i.Environment,
			&i.Team,
			&i.Email,
			&i.RegularExpression,
			pq.Array(&i.ValidSubjectAlternateName),
			pq.Array(&i.ValidCertificateAuthorities),
			&i.ExtendedKey,
			&i.CertificateValidity,
			&i.SubordinateCa,
			pq.Array(&i.NodeAttestation),
			&i.CreatedAt,
			&i.CreatedBy,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateInstanceIdentityNodeAttestor = `-- name: UpdateInstanceIdentityNodeAttestor :one
UPDATE accounts
SET 
    node_attestation = $2
WHERE client_id = $1
RETURNING client_id, api_token, service_account, environment, team, email, regular_expression, valid_subject_alternate_name, valid_certificate_authorities, extended_key, certificate_validity, subordinate_ca, node_attestation, created_at, created_by
`

type UpdateInstanceIdentityNodeAttestorParams struct {
	ClientID        uuid.UUID `json:"client_id"`
	NodeAttestation []string  `json:"node_attestation"`
}

func (q *Queries) UpdateInstanceIdentityNodeAttestor(ctx context.Context, arg UpdateInstanceIdentityNodeAttestorParams) (*Account, error) {
	row := q.db.QueryRowContext(ctx, updateInstanceIdentityNodeAttestor, arg.ClientID, pq.Array(arg.NodeAttestation))
	var i Account
	err := row.Scan(
		&i.ClientID,
		&i.ApiToken,
		&i.ServiceAccount,
		&i.Environment,
		&i.Team,
		&i.Email,
		&i.RegularExpression,
		pq.Array(&i.ValidSubjectAlternateName),
		pq.Array(&i.ValidCertificateAuthorities),
		&i.ExtendedKey,
		&i.CertificateValidity,
		&i.SubordinateCa,
		pq.Array(&i.NodeAttestation),
		&i.CreatedAt,
		&i.CreatedBy,
	)
	return &i, err
}

const updateServiceAccount = `-- name: UpdateServiceAccount :one
UPDATE accounts
SET 
    environment = $2,
    team = $3,
    email = $4,
    regular_expression = $5,
    valid_subject_alternate_name = $6,
    valid_certificate_authorities = $7,
    extended_key = $8,
    certificate_validity = $9,
    subordinate_ca = $10,
    node_attestation = $11
WHERE client_id = $1
RETURNING client_id, api_token, service_account, environment, team, email, regular_expression, valid_subject_alternate_name, valid_certificate_authorities, extended_key, certificate_validity, subordinate_ca, node_attestation, created_at, created_by
`

type UpdateServiceAccountParams struct {
	ClientID                    uuid.UUID      `json:"client_id"`
	Environment                 string         `json:"environment"`
	Team                        string         `json:"team"`
	Email                       string         `json:"email"`
	RegularExpression           sql.NullString `json:"regular_expression"`
	ValidSubjectAlternateName   []string       `json:"valid_subject_alternate_name"`
	ValidCertificateAuthorities []string       `json:"valid_certificate_authorities"`
	ExtendedKey                 string         `json:"extended_key"`
	CertificateValidity         int16          `json:"certificate_validity"`
	SubordinateCa               string         `json:"subordinate_ca"`
	NodeAttestation             []string       `json:"node_attestation"`
}

func (q *Queries) UpdateServiceAccount(ctx context.Context, arg UpdateServiceAccountParams) (*Account, error) {
	row := q.db.QueryRowContext(ctx, updateServiceAccount,
		arg.ClientID,
		arg.Environment,
		arg.Team,
		arg.Email,
		arg.RegularExpression,
		pq.Array(arg.ValidSubjectAlternateName),
		pq.Array(arg.ValidCertificateAuthorities),
		arg.ExtendedKey,
		arg.CertificateValidity,
		arg.SubordinateCa,
		pq.Array(arg.NodeAttestation),
	)
	var i Account
	err := row.Scan(
		&i.ClientID,
		&i.ApiToken,
		&i.ServiceAccount,
		&i.Environment,
		&i.Team,
		&i.Email,
		&i.RegularExpression,
		pq.Array(&i.ValidSubjectAlternateName),
		pq.Array(&i.ValidCertificateAuthorities),
		&i.ExtendedKey,
		&i.CertificateValidity,
		&i.SubordinateCa,
		pq.Array(&i.NodeAttestation),
		&i.CreatedAt,
		&i.CreatedBy,
	)
	return &i, err
}