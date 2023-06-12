-- name: CreateUser :one
INSERT INTO users (
    uuid,
    username,
    hashed_credential,
    full_name,
    email,
    permissions
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetUser :one
SELECT * FROM users
WHERE username = $1 LIMIT 1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY username
LIMIT $1
OFFSET $2;

-- name: UpdateUserAuthentication :one
UPDATE users 
SET hashed_credential = $2, credential_changed_at = now() 
WHERE username = $1
RETURNING *;

-- name: UpdateUserPermission :one
UPDATE users
SET permissions = $2
WHERE username = $1
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users 
WHERE username = $1;