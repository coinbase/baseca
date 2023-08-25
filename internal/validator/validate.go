package validator

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"unicode"

	"github.com/coinbase/baseca/internal/config"
	"github.com/tabbed/pqtype"
)

type NullString sql.NullString

func ValidateCertificateAuthorityEnvironment(config config.Environment, environment string, certificate_authorities []string) bool {
	if len(certificate_authorities) == 0 {
		return false
	}

	for _, certificate_authority := range certificate_authorities {
		if output := Contains(CertificateAuthorityEnvironments[environment], certificate_authority); !output {
			return false
		}
	}
	return true
}

func ValidateSubjectAlternateNames(request_san []string, valid_san []string, regular_expression string) error {
	mapping := make(map[string]bool)
	for _, elem := range valid_san {
		mapping[elem] = true
	}

	// Non-Regex Check
	if len(regular_expression) == 0 {
		for _, san := range request_san {
			if !mapping[san] {
				return fmt.Errorf("invalid subject alternative name [%s]", san)
			}
		}
	} else { // Regex Check
		for _, san := range request_san {
			if !mapping[san] {
				compile, err := regexp.Compile(regular_expression)
				if err != nil {
					return fmt.Errorf("regular expression compile error: %s", err)
				}
				match := compile.MatchString(san)
				if !match {
					return fmt.Errorf("invalid subject alternative name [%s] from regular expression validation", san)
				}
			}
		}
	}
	return nil
}

func ValidateEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(email)
}

func NullStringToString(x *sql.NullString) string {
	if x.Valid {
		return x.String
	}
	return ""
}

func MapToNullRawMessage(m map[string]string) (pqtype.NullRawMessage, error) {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return pqtype.NullRawMessage{}, err
	}

	nullRawMessage := pqtype.NullRawMessage{}
	err = nullRawMessage.Scan(jsonBytes)
	if err != nil {
		return pqtype.NullRawMessage{}, err
	}

	return nullRawMessage, nil
}

func ConvertNullRawMessageToMap(nrm pqtype.NullRawMessage) (map[string]string, error) {
	if !nrm.Valid {
		return nil, nil
	}

	var m map[string]interface{}
	err := json.Unmarshal(nrm.RawMessage, &m)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			result[k] = s
		}
	}
	return result, nil
}

// Validate if input only contain alphanumeric
func ValidateInput(s string) bool {
	for _, c := range s {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) {
			return false
		}
	}

	return true
}
