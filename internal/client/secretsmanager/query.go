package secretsmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	secretsmanager_v2 "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const (
	DATABASE_CREDENTIALS = "password"
	AUTH_PRIVATE_KEY     = "auth_private_key"
	AUTH_PUBLIC_KEY      = "auth_public_key"
)

func (s *SecretsManagerClient) GetSecretValue(id string, key string) (*string, error) {
	envValue, exists := os.LookupEnv(key)
	if exists {
		return &envValue, nil
	}

	input := &secretsmanager_v2.GetSecretValueInput{
		SecretId: &id,
	}

	result, err := s.Client.GetSecretValue(context.Background(), input)
	if err != nil {
		return nil, err
	}

	var data map[string]string
	err = json.Unmarshal([]byte(*result.SecretString), &data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshal secrets manager data %s", id)
	}

	value, ok := data[key]
	if !ok {
		return nil, fmt.Errorf("key %s not found in secrets manager %s", key, id)
	}

	return &value, nil
}
