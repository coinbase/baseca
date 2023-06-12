package types

import (
	"time"

	"github.com/google/uuid"
)

type ServiceAccount struct {
	ClientID                    uuid.UUID       `json:"client_id"`
	ApiToken                    string          `json:"api_token,omitempty" `
	ServiceAccount              string          `json:"service_account"`
	Environment                 string          `json:"environment,omitempty"`
	Team                        string          `json:"team"`
	Email                       string          `json:"email"`
	SANRegularExpression        string          `json:"regular_expression,omitempty"`
	ValidSubjectAlternateName   []string        `json:"valid_subject_alternate_name"`
	ValidCertificateAuthorities []string        `json:"valid_certificate_authorities"`
	CertificateValidity         int16           `json:"certificate_validity"`
	ExtendedKey                 string          `json:"extended_key"`
	NodeAttestation             NodeAttestation `json:"node_attestation"`
	CreatedAt                   time.Time       `json:"created_at"`
	CreatedBy                   uuid.UUID       `json:"created_by"`
}
