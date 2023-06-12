package authentication

import (
	"errors"

	"github.com/google/uuid"
)

var (
	ErrExpiredToken = errors.New("token has expired")
	ErrInvalidToken = errors.New("token is invalid")
)

type ServicePayload struct {
	ServiceID                   uuid.UUID `json:"service_id"`
	ServiceAccount              string    `json:"service_account"`
	Environment                 string    `json:"environment"`
	ValidSubjectAlternateName   []string  `json:"subject_alternate_name"`
	ValidCertificateAuthorities []string  `json:"certificate_authorities"`
	CertificateValidity         int16     `json:"certificate_validity"`
	SubordinateCa               string    `json:"subordinate_ca"`
	ExtendedKey                 string    `json:"certificate_request_extension"`
	SANRegularExpression        string    `json:"regular_expression"`
}

type EnrollmentPayload struct {
	SerialNumber string `json:"serial_number"`
}
