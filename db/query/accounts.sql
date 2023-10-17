-- name: CreateServiceAccount :one
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
    provisioned,
    node_attestation,
    created_at,
    created_by
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
) RETURNING *;

-- name: GetServiceUUID :one
SELECT * FROM accounts
WHERE client_id = $1;

-- name: GetServiceAccounts :many
SELECT * FROM accounts
WHERE service_account = $1;

-- name: ListServiceAccounts :many
SELECT * FROM accounts
ORDER BY service_account
LIMIT $1
OFFSET $2;

-- name: UpdateServiceAccount :one
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
RETURNING *;

-- name: UpdateInstanceIdentityNodeAttestor :one
UPDATE accounts
SET 
    node_attestation = $2
WHERE client_id = $1
RETURNING *;

-- name: DeleteServiceAccount :exec
DELETE FROM accounts 
WHERE client_id = $1;

-- name: GetServiceAccountBySAN :many
SELECT * FROM accounts
WHERE valid_subject_alternate_name = ANY($1::string[]);

-- name: GetServiceAccountByMetadata :many
SELECT * FROM accounts
WHERE service_account LIKE $1 AND environment LIKE $2 AND extended_key LIKE $3;

-- name: ListValidCertificateAuthorityFromSubordinateCA :many
SELECT DISTINCT unnest(valid_certificate_authorities) AS certificate_authorities
FROM accounts
WHERE subordinate_ca = $1 AND environment = $2;
