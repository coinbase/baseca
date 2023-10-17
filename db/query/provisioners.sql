-- name: CreateProvisionerAccount :one
INSERT INTO provisioners (
    client_id,
    api_token,
    provisioner_account,
    environments,
    team,
    email,
    regular_expression,
    node_attestation,
    valid_subject_alternate_names,
    extended_keys,
    max_certificate_validity,
    created_at,
    created_by
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
) RETURNING *;

-- name: GetProvisionerUUID :one
SELECT * FROM provisioners
WHERE client_id = $1;

-- name: DeleteProvisionerAccount :exec
DELETE FROM provisioners 
WHERE client_id = $1;

-- name: ListProvisionerAccounts :many
SELECT * FROM provisioners
LIMIT $1
OFFSET $2;