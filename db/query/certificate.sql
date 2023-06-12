-- name: LogCertificate :one
INSERT INTO certificates (
    serial_number,
    account,
    environment,
    extended_key,
    common_name,
    subject_alternative_name,
    expiration_date,
    issued_date,
    certificate_authority_arn
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
) RETURNING *;

-- name: GetCertificate :one
SELECT * FROM certificates
WHERE serial_number = $1;

-- name: ListCertificateSubjectAlternativeName :many
SELECT * FROM certificates
WHERE common_name = $1 OR $1 = ANY(subject_alternative_name)
LIMIT $2
OFFSET $3;

-- name: ListCertificates :many
SELECT * FROM certificates
ORDER BY certificates
LIMIT $1
OFFSET $2;

-- name: RevokeIssuedCertificateSerialNumber :exec
UPDATE certificates
SET revoked = TRUE, revoke_date = $2, revoked_by = $3
WHERE serial_number = $1;