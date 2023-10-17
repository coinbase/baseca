package validator

import (
	"reflect"
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
			RequestSAN:        []string{"example.com"},
		},
		{
			RegularExpression: `^[a-zA-Z]+((!coinbase.com)\w)*$`,
			ValidSAN:          []string{"*.coinbase.com"},
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

func Test_Contains(t *testing.T) {
	s := []string{"a", "b", "c"}

	if !Contains(s, "a") {
		t.Error("Expected slice to contain 'a'")
	}

	if Contains(s, "d") {
		t.Error("Did not expect slice to contain 'd'")
	}
}

func Test_SanitizeInput(t *testing.T) {
	input := []string{"a", "b", "a", "c", "c"}
	expected := []string{"a", "b", "c"}

	result := SanitizeInput(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}
