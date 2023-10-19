package users

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	mock_store "github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	"github.com/coinbase/baseca/internal/config"
	lib "github.com/coinbase/baseca/internal/lib/authentication"
	"github.com/stretchr/testify/mock"
)

type mockedKmsClient struct {
	mock.Mock
}

func (m *mockedKmsClient) Sign(ctx context.Context, signInput *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	ret := m.Called(ctx, signInput, opts)
	return ret.Get(0).(*kms.SignOutput), ret.Error(1)
}

func (m *mockedKmsClient) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	ret := m.Called(ctx, params, optFns)
	return ret.Get(0).(*kms.VerifyOutput), ret.Error(1)
}

func buildUsersConfig(store *mock_store.MockStore) (*User, error) {
	config, err := config.GetTestConfigurationPath()
	if err != nil {
		return nil, err
	}

	mockKms := &mockedKmsClient{}
	mockKms.On("Sign", mock.Anything, mock.Anything, mock.Anything).Return(
		&kms.SignOutput{
			Signature: []byte("signature"),
		}, nil,
	)

	signer := &lib.Client{
		KmsClient:        mockKms,
		KeyId:            config.KMS.KeyId,
		SigningAlgorithm: config.KMS.SigningAlgorithm,
	}

	auth, err := lib.NewAuthSigningMetadata(signer)
	if err != nil {
		return nil, err
	}

	endpoints := db.DatabaseEndpoints{Writer: store, Reader: store}

	return &User{
		store:    endpoints,
		auth:     auth,
		validity: config.KMS.AuthValidity,
	}, nil
}
