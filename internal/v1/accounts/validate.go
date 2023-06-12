package accounts

import (
	"context"
	"fmt"
	"regexp"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/validator"
)

const (
	_role_regex_pattern  = `^arn:aws:iam::\d{12}:role\/[a-zA-Z_0-9+=,.@-]+$`
	_sg_regex_pattern    = `^sg-[a-zA-Z0-9]+$`
	_instance_id_pattern = `^i-[a-fA-F0-9]{8,17}$`
)

// Create Service Account: Check if Same SAN Exists within Other Service Account
func (s *Service) validateSanInput(ctx context.Context, service_account string, environment string, request_san []string, pattern *string) error {
	var page_id = int32(1)
	var page_size = int32(25)
	var sans [][]string

	if len(service_account) == 0 {
		return fmt.Errorf("invalid service_account parameter")
	}

	if pattern == nil && len(request_san) == 0 {
		return fmt.Errorf("subject_alternative_names and regular_expression cannot both be empty")
	}

	if pattern != nil {
		_, err := regexp.Compile(*pattern)
		if err != nil {
			return fmt.Errorf("invalid regular_expressing pattern")
		}
	}

	for _, fqdn := range request_san {
		if !validator.IsValidateDomain(fqdn) {
			return fmt.Errorf("invalid domain [%s]", fqdn)
		}
	}

	for {
		arg := db.ListServiceAccountsParams{
			Limit:  page_size,
			Offset: (page_id - 1) * page_size,
		}
		services, err := s.store.Reader.ListServiceAccounts(ctx, arg)
		if err != nil {
			return fmt.Errorf("error listing service accounts during san validation")
		}
		if len(services) == 0 {
			break
		}
		for _, elem := range services {
			// Do Not Include Service Account with Same Name and Environment
			if service_account == elem.ServiceAccount && environment == elem.Environment {
				continue
			}
			sans = append(sans, elem.ValidSubjectAlternateName)
		}
		page_id += 1
	}

	for _, san := range sans {
		for _, elem := range san {
			if validator.Contains(request_san, elem) {
				return fmt.Errorf("subject alternative name (san) %s exists in another service account", request_san)
			}
		}
	}

	return nil
}

func (s *Service) validateCertificateParameters(certificateAuthorities []string, environment string, certificateValidity int16, subordinateCa string) error {
	if _, ok := validator.CertificateAuthorityEnvironments[environment]; !ok {
		return fmt.Errorf("invalid environment [%s]", environment)
	}

	// Determine Allowed CA within Environment (Service Account Cannot Access CA from Multiple Environments)
	if output := validator.ValidateCertificateAuthorityEnvironment(s.environment, environment, certificateAuthorities); !output {
		return fmt.Errorf("invalid certificate authorities input %s", certificateAuthorities)
	}

	if len(subordinateCa) == 0 {
		return fmt.Errorf("invalid subordinate_ca parameter")
	}

	// Determine Certificate Validity Greater than CA Validity
	if certificateValidity <= 0 {
		return fmt.Errorf("invalid certificate_validity parameter")
	}

	for _, certificateAuthority := range certificateAuthorities {
		caValidity := s.acmConfig[certificateAuthority].CaActiveDay
		if caValidity <= int(certificateValidity) {
			return fmt.Errorf("certificate expiration [%d] exceeds certificate authority [%s] validity [%d]", certificateValidity, certificateAuthority, caValidity)
		}
	}

	return nil
}

func validateNodeAttestation(attestation *apiv1.NodeAttestation) error {
	if attestation == nil {
		return fmt.Errorf("node_attestation cannot be empty")
	}

	if attestation.AwsIid == nil {
		return fmt.Errorf("aws_iid cannot be empty")
	}

	if err := validateAwsIidMetadata(attestation.AwsIid); err != nil {
		return err
	}

	return nil
}

func validateAwsIidMetadata(iid *apiv1.AWSInstanceIdentityDocument) error {
	var err bool
	var validAttestation = false

	if iid.RoleArn != "" {
		err = validateRegularExpression(iid.RoleArn, _role_regex_pattern)
		if err {
			return fmt.Errorf("invalid aws_iid instance role arn [%s]", iid.RoleArn)
		}
		validAttestation = true
	}

	if iid.AssumeRole != "" {
		err = validateRegularExpression(iid.AssumeRole, _role_regex_pattern)
		if err {
			return fmt.Errorf("invalid aws_iid assume role arn [%s]", iid.AssumeRole)
		}
		validAttestation = true
	}

	if len(iid.SecurityGroups) != 0 {
		for _, sg := range iid.SecurityGroups {
			err = validateRegularExpression(sg, _sg_regex_pattern)
			if err {
				return fmt.Errorf("invalid aws_iid security group id [%s]", sg)
			}
		}
		validAttestation = true
	}

	if iid.Region != "" {
		validRegion := validAWSRegion(iid.Region)
		if !validRegion {
			return fmt.Errorf("invalid aws_iid region [%s]", iid.Region)
		}
		validAttestation = true
	}

	if iid.InstanceId != "" {
		err = validateRegularExpression(iid.InstanceId, _instance_id_pattern)
		if err {
			return fmt.Errorf("invalid aws_iid instance id [%s]", iid.InstanceId)
		}
		validAttestation = true
	}

	if !validAttestation {
		return fmt.Errorf("aws_iid attestation empty")
	}

	return nil
}

func validateRegularExpression(input string, pattern string) bool {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return true
	}

	if regex.MatchString(input) {
		return false
	}
	return true
}

func validAWSRegion(region string) bool {
	validRegions := map[string]bool{
		"us-east-1":      true,
		"us-east-2":      true,
		"us-west-1":      true,
		"us-west-2":      true,
		"af-south-1":     true,
		"ap-east-1":      true,
		"ap-south-1":     true,
		"ap-northeast-3": true,
		"ap-northeast-2": true,
		"ap-southeast-1": true,
		"ap-southeast-2": true,
		"ap-northeast-1": true,
		"ca-central-1":   true,
		"eu-central-1":   true,
		"eu-west-1":      true,
		"eu-west-2":      true,
		"eu-south-1":     true,
		"eu-west-3":      true,
		"eu-north-1":     true,
		"me-south-1":     true,
		"sa-east-1":      true,
	}
	_, isValid := validRegions[region]
	return isValid
}
