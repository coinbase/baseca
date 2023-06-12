package secretsmanager

import (
	"context"
	"fmt"

	config_v2 "github.com/aws/aws-sdk-go-v2/config"
	secretsmanager_v2 "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/coinbase/baseca/internal/config"
)

type SecretsManagerClientIface interface {
	GetSecretValue(ctx context.Context, params *secretsmanager_v2.GetSecretValueInput, optFns ...func(*secretsmanager_v2.Options)) (*secretsmanager_v2.GetSecretValueOutput, error)
}

type SecretsManagerClient struct {
	Client SecretsManagerClientIface
}

func NewSecretsManagerClient(config *config.Config) (*SecretsManagerClient, error) {
	cfg, err := config_v2.LoadDefaultConfig(context.TODO(),
		config_v2.WithRegion(config.SecretsManager.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create new session: %s", err)
	}

	return &SecretsManagerClient{
		Client: secretsmanager_v2.NewFromConfig(cfg),
	}, nil
}
