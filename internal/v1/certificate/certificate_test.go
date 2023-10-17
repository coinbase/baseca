package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	firehose_v2 "github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go/aws"
	mock_store "github.com/coinbase/baseca/db/mock"
	db "github.com/coinbase/baseca/db/sqlc"
	acm_pca "github.com/coinbase/baseca/internal/client/acmpca"
	"github.com/coinbase/baseca/internal/client/firehose"
	redis_client "github.com/coinbase/baseca/internal/client/redis"
	"github.com/coinbase/baseca/internal/lib/util/validator"
	"github.com/coinbase/baseca/test"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/mock"
)

var csr *acmpca.IssueCertificateInput
var rootCrt string

var pk *rsa.PrivateKey
var root []byte
var template *x509.Certificate

type mockedRedisClient struct {
	mock.Mock
}

func (m *mockedRedisClient) HIncrBy(ctx context.Context, key, field string, incr int64) *redis.IntCmd {
	ret := m.Called(ctx, key, field, incr)
	return ret.Get(0).(*redis.IntCmd)
}

func (m *mockedRedisClient) HGetAll(ctx context.Context, key string) *redis.StringStringMapCmd {
	ret := m.Called(ctx, key)
	return ret.Get(0).(*redis.StringStringMapCmd)
}

func (m *mockedRedisClient) HDel(ctx context.Context, key string, fields ...string) *redis.IntCmd {
	ret := m.Called(ctx, key, fields)
	return ret.Get(0).(*redis.IntCmd)
}

func (m *mockedRedisClient) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	ret := m.Called(ctx, key, expiration)
	return ret.Get(0).(*redis.BoolCmd)
}

type mockedFirehoseClient struct {
	mock.Mock
}

func (m *mockedFirehoseClient) PutRecord(ctx context.Context, params *firehose_v2.PutRecordInput, optFns ...func(*firehose_v2.Options)) (*firehose_v2.PutRecordOutput, error) {
	ret := m.Called(ctx, params)
	return ret.Get(0).(*firehose_v2.PutRecordOutput), ret.Error(1)
}

type mockedPrivateCaClient struct {
	mock.Mock
}

func (m *mockedPrivateCaClient) IssueCertificate(ctx context.Context, params *acmpca.IssueCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.IssueCertificateOutput, error) {
	ret := m.Called(ctx, params, optFns)
	return ret.Get(0).(*acmpca.IssueCertificateOutput), ret.Error(1)
}

func (m *mockedPrivateCaClient) GetCertificate(ctx context.Context, params *acmpca.GetCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.GetCertificateOutput, error) {
	certificate, _ := convertX509toString(root)
	rootCrt = certificate.String()

	block, _ := pem.Decode(csr.Csr)
	req, _ := x509.ParseCertificateRequest(block.Bytes)

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      req.Subject,
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().Add(60 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &certTemplate, template, req.PublicKey, pk)
	cert, _ := convertX509toString(certDER)
	c := cert.String()
	crtOutput := &c

	certOutput := &acmpca.GetCertificateOutput{
		Certificate:      crtOutput,
		CertificateChain: crtOutput,
	}

	return certOutput, nil
}

func (m *mockedPrivateCaClient) RevokeCertificate(ctx context.Context, params *acmpca.RevokeCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.RevokeCertificateOutput, error) {
	ret := m.Called(ctx, params, optFns)
	return ret.Get(0).(*acmpca.RevokeCertificateOutput), ret.Error(1)
}

func (m *mockedPrivateCaClient) GetCertificateAuthorityCertificate(ctx context.Context, params *acmpca.GetCertificateAuthorityCertificateInput, optFns ...func(*acmpca.Options)) (*acmpca.GetCertificateAuthorityCertificateOutput, error) {
	ret := m.Called(ctx, params, optFns)
	return ret.Get(0).(*acmpca.GetCertificateAuthorityCertificateOutput), ret.Error(1)
}

func buildCertificateConfig(store *mock_store.MockStore) (*Certificate, error) {
	config, err := test.GetTestConfigurationPath()
	if err != nil {
		return nil, err
	}

	validator.SupportedConfig(config)
	validator.SetBaseDirectory(config)
	validator.SupportedEnvironments(config)

	endpoints := db.DatabaseEndpoints{Writer: store, Reader: store}
	redisConfig := &config.Redis
	mockRedis := &mockedRedisClient{}

	mockRedis.On("HIncrBy", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(redis.NewIntCmd(context.Background(), "example.com", time.Now().UTC(), int64(10)))

	mockRedis.On("HGetAll", mock.Anything, mock.Anything).
		Return(redis.NewStringStringMapCmd(context.Background(), map[string]string{"example.com": time.Now().UTC().String()}))

	mockRedis.On("Expire")
	mockRedis.On("HDel")

	redisClient := redis_client.RedisClient{
		Client: mockRedis,
		Config: redisConfig,
		Limit:  redisConfig.RateLimit,
		Period: time.Duration(redisConfig.Period) * time.Minute,
		Window: time.Duration(redisConfig.Duration) * time.Minute,
	}

	mockFirehose := &mockedFirehoseClient{}
	mockFirehose.On("PutRecord", mock.Anything, mock.Anything, mock.Anything).
		Return(&firehose_v2.PutRecordOutput{
			RecordId:  aws.String(mock.Anything),
			Encrypted: aws.Bool(true),
		}, nil)

	firehoseClient := firehose.FirehoseClient{
		DataStream: config.Firehose.Stream,
		Service:    mockFirehose,
	}

	mockPrivateCa := &mockedPrivateCaClient{}
	mockPrivateCa.On("IssueCertificate", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		certificateInput := args.Get(1)
		csr, _ = certificateInput.(*acmpca.IssueCertificateInput)
	}).Return(&acmpca.IssueCertificateOutput{
		CertificateArn: aws.String(mock.Anything),
	}, nil)

	mockPrivateCa.On("GetCertificate", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockPrivateCa.On("GetCertificateAuthorityCertificate", mock.Anything, mock.Anything, mock.Anything).
		Return(&acmpca.GetCertificateAuthorityCertificateOutput{
			Certificate:      &rootCrt,
			CertificateChain: &rootCrt,
		}, nil)

	privateCaClient := acm_pca.PrivateCaClient{
		Client: mockPrivateCa,
	}

	pk, template, root = mockRootCertificateAuthority()

	return &Certificate{
		store:       endpoints,
		acmConfig:   config.ACMPCA,
		ca:          config.SubordinateMetadata,
		environment: config.Environment,
		redis:       &redisClient,
		firehose:    &firehoseClient,
		pca:         &privateCaClient,
	}, nil
}

func mockRootCertificateAuthority() (*rsa.PrivateKey, *x509.Certificate, []byte) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Unit Test Root CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	return rootKey, &rootTemplate, rootCertDER
}
