package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestValidate struct {
	RegularExpression string
	ValidSAN          []string
	RequestSAN        []string
}

func Test_ValidateSubjectAlternateNames_Regex_Error(t *testing.T) {
	test_validator := []TestValidate{
		{
			RegularExpression: `^[a-zA-Z]+((!coinbase.com)\w)*$`,
			ValidSAN:          []string{},
			RequestSAN:        []string{"example.coinbase.com"},
		},
		{
			RegularExpression: `^[a-zA-Z]+((!coinbase.com)\w)*$`,
			ValidSAN:          []string{""},
			RequestSAN:        []string{"12345"},
		},
	}

	for _, elem := range test_validator {
		err := ValidateSubjectAlternateNames(elem.RequestSAN, elem.ValidSAN, elem.RegularExpression)
		assert.Error(t, err)
	}
}

func Test_ValidateSubjectAlternateNames_Success(t *testing.T) {
	test_validator := []TestValidate{
		{
			RegularExpression: `^[a-zA-Z]+((!coinbase.com)\w)*$`,
			ValidSAN:          []string{},
			RequestSAN:        []string{"baseca"},
		},
	}

	for _, elem := range test_validator {
		err := ValidateSubjectAlternateNames(elem.RequestSAN, elem.ValidSAN, elem.RegularExpression)
		assert.NoError(t, err)
	}
}

func Test_ValidateSubjectAlternateNames_ValidSAN_Regex_Success(t *testing.T) {
	test_validator := []TestValidate{
		{
			RegularExpression: `^[a-zA-Z]+((!coinbase.com)\w)*$`,
			ValidSAN:          []string{"10.0.0.1"},
			RequestSAN:        []string{"10.0.0.1"},
		},
	}

	for _, elem := range test_validator {
		err := ValidateSubjectAlternateNames(elem.RequestSAN, elem.ValidSAN, elem.RegularExpression)
		assert.NoError(t, err)
	}
}
