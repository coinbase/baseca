package types

import (
	"github.com/google/uuid"
)

type ServiceAccountPayload struct {
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

type ProvisionerAccountPayload struct {
	ClientId                   uuid.UUID `json:"client_id"`
	ProvisionerAccount         string    `json:"provisioner_account"`
	Environments               []string  `json:"environments"`
	ValidSubjectAlternateNames []string  `json:"subject_alternate_names"`
	MaxCertificateValidity     uint32    `json:"max_certificate_validity"`
	ExtendedKeys               []string  `json:"certificate_request_extension"`
	RegularExpression          string    `json:"regular_expression"`
}
