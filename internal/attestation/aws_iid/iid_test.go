package aws_iid

import (
	"testing"
)

func TestIsValidRoleArn(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want bool
	}{
		{
			name: "Valid ARN",
			arn:  "arn:aws:iam::123456789012:role/Example",
			want: true,
		},
		{
			name: "Invalid ARN",
			arn:  "invalid:arn:format",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidRoleArn(tt.arn)
			if got != tt.want {
				t.Errorf("isValidRoleArn() = %v, want %v", got, tt.want)
			}
		})
	}
}
