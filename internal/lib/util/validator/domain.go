package validator

import (
	"net"
	"regexp"
	"strings"

	"github.com/coinbase/baseca/internal/config"
)

const (
	_dns_regular_expression = `^[a-zA-Z*.]+$`
)

var valid_domains []string
var valid_certificate_authorities []string

func IsValidDomain(fully_qualified_domain_name string) bool {

	arr := strings.Split(fully_qualified_domain_name, ".")

	if len(arr) < 2 {
		return false
	}

	domain_slice := arr[len(arr)-2:]
	domain := strings.Join(domain_slice, ".")
	pattern, _ := regexp.Compile(_dns_regular_expression)

	for _, valid_domain := range valid_domains {
		if domain == valid_domain {
			// DNS Wildcard Check
			if pattern.MatchString(fully_qualified_domain_name) {
				return true
			}
		}
	}

	// Fallback Check IP Address for CN/SAN
	return net.ParseIP(fully_qualified_domain_name) != nil
}

func IsSupportedCertificateAuthority(certificate_authority string) bool {
	for _, ca := range valid_certificate_authorities {
		if ca == certificate_authority {
			return true
		}
	}
	return false
}

func SupportedConfig(cfg *config.Config) {
	valid_domains = cfg.Domains

	for certificate_authority := range cfg.ACMPCA {
		valid_certificate_authorities = append(valid_certificate_authorities, certificate_authority)
	}
}
