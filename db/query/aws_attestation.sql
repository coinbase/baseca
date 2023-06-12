-- name: StoreInstanceIdentityDocument :one
INSERT into aws_attestation (
  client_id,
  role_arn,
  assume_role,
  security_group_id,
  region,
  instance_id,
  image_id,
  instance_tags
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;

-- name: GetInstanceIdentityDocument :one
SELECT * from aws_attestation 
WHERE client_id = $1;

-- name: DeleteInstanceIdentityDocument :exec
DELETE FROM aws_attestation 
WHERE client_id = $1;