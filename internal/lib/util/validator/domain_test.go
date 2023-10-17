package validator

import (
	"testing"

	"github.com/coinbase/baseca/internal/config"
)

func TestIsValidateDomain(t *testing.T) {
	valid_domains = []string{"coinbase.com"}

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"Valid Domain", "www.coinbase.com", true},
		{"Invalid Domain", "www.invalid.com", false},
		{"Valid IP Address", "192.168.1.1", true},
		{"Invalid String", "coinbase", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidDomain(tt.domain); got != tt.want {
				t.Errorf("IsValidateDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSupportedCertificateAuthority(t *testing.T) {
	// Setup
	valid_certificate_authorities = []string{"certificate_authority_1", "certificate_authority_2"}

	if !IsSupportedCertificateAuthority("certificate_authority_1") {
		t.Error("Expected certificate_authority_1 to be supported")
	}

	if IsSupportedCertificateAuthority("certificate_authority_3") {
		t.Error("Expected certificate_authority_3 not to be supported")
	}
}

func TestSupportedConfig(t *testing.T) {
	cfg := &config.Config{
		Domains: []string{"domain1.com", "domain2.com"},
		ACMPCA: map[string]config.SubordinateCertificate{
			"certificate_authority_1": {
				Region: "us-west-1",
			},
			"certificate_authority_2": {
				Region: "us-east-1",
			},
		},
	}

	SupportedConfig(cfg)

	if !Contains(valid_domains, "domain1.com") {
		t.Error("Expected domain1.com to be in valid_domains")
	}

	if !Contains(valid_certificate_authorities, "certificate_authority_1") {
		t.Error("Expected certificate_authority_1 to be in valid_certificate_authorities")
	}
}
