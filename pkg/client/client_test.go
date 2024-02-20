package baseca

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		attestation string
		options     []ClientOptions
		check       func(t *testing.T, c *Client, err error)
	}{
		{
			name:        "OK_Local_Configuration_Client_Id_Client_Token",
			endpoint:    "localhost:9090",
			attestation: Attestation.Local,
			options:     []ClientOptions{WithClientId("client_id"), WithClientToken("client_token")},
			check: func(t *testing.T, c *Client, err error) {
				assert.NoError(t, err)
				assert.Equal(t, "client_id", c.Authentication.ClientId)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.endpoint, tc.attestation, tc.options...)
			tc.check(t, c, err)
		})
	}
}
