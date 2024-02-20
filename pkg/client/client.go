package baseca

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/pkg/attestor/aws_iid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	_client_id_header    = "X-BASECA-CLIENT-ID"
	_client_token_header = "X-BASECA-CLIENT-TOKEN" // #nosec G101 False Positive
	_aws_iid_metadata    = "X-BASECA-INSTANCE-METADATA"
	_account_auth_header = "AUTHORIZATION"
)

type Client struct {
	Endpoint       string
	Authentication Authentication
	Attestation    string
	Certificate    apiv1.CertificateClient
	Account        AccountClient
	Service        apiv1.ServiceClient
	Insecure       bool
	*iidCache
}

type ClientOptions func(*Client) error

type AccountClient interface {
	LoginUser(ctx context.Context, in *apiv1.LoginUserRequest, opts ...grpc.CallOption) (*apiv1.LoginUserResponse, error)
	DeleteUser(ctx context.Context, in *apiv1.UsernameRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	GetUser(ctx context.Context, in *apiv1.UsernameRequest, opts ...grpc.CallOption) (*apiv1.User, error)
	ListUsers(ctx context.Context, in *apiv1.QueryParameter, opts ...grpc.CallOption) (*apiv1.Users, error)
	CreateUser(ctx context.Context, in *apiv1.CreateUserRequest, opts ...grpc.CallOption) (*apiv1.User, error)
	UpdateUserCredentials(ctx context.Context, in *apiv1.UpdateCredentialsRequest, opts ...grpc.CallOption) (*apiv1.User, error)
	UpdateUserPermissions(ctx context.Context, in *apiv1.UpdatePermissionsRequest, opts ...grpc.CallOption) (*apiv1.User, error)
}

type CertificateClient interface {
	SignCSR(ctx context.Context, in *apiv1.CertificateSigningRequest, opts ...grpc.CallOption) (*apiv1.SignedCertificate, error)
	GetCertificate(ctx context.Context, in *apiv1.CertificateSerialNumber, opts ...grpc.CallOption) (*apiv1.CertificateParameter, error)
	ListCertificates(ctx context.Context, in *apiv1.ListCertificatesRequest, opts ...grpc.CallOption) (*apiv1.CertificatesParameter, error)
	RevokeCertificate(ctx context.Context, in *apiv1.RevokeCertificateRequest, opts ...grpc.CallOption) (*apiv1.RevokeCertificateResponse, error)
	OperationsSignCSR(ctx context.Context, in *apiv1.OperationsSignRequest, opts ...grpc.CallOption) (*apiv1.SignedCertificate, error)
	QueryCertificateMetadata(ctx context.Context, in *apiv1.QueryCertificateMetadataRequest, opts ...grpc.CallOption) (*apiv1.CertificatesParameter, error)
}

type ServiceClient interface {
	CreateServiceAccount(ctx context.Context, in *apiv1.CreateServiceAccountRequest, opts ...grpc.CallOption) (*apiv1.CreateServiceAccountResponse, error)
	CreateProvisionerAccount(ctx context.Context, in *apiv1.CreateProvisionerAccountRequest, opts ...grpc.CallOption) (*apiv1.CreateProvisionerAccountResponse, error)
	GetProvisionerAccount(ctx context.Context, in *apiv1.AccountId, opts ...grpc.CallOption) (*apiv1.ProvisionerAccount, error)
	ListProvisionerAccounts(ctx context.Context, in *apiv1.QueryParameter, opts ...grpc.CallOption) (*apiv1.ProvisionerAccounts, error)
	ProvisionServiceAccount(ctx context.Context, in *apiv1.ProvisionServiceAccountRequest, opts ...grpc.CallOption) (*apiv1.ProvisionServiceAccountResponse, error)
	ListServiceAccounts(ctx context.Context, in *apiv1.QueryParameter, opts ...grpc.CallOption) (*apiv1.ServiceAccounts, error)
	GetServiceAccount(ctx context.Context, in *apiv1.AccountId, opts ...grpc.CallOption) (*apiv1.ServiceAccount, error)
	GetServiceAccountMetadata(ctx context.Context, in *apiv1.GetServiceAccountMetadataRequest, opts ...grpc.CallOption) (*apiv1.ServiceAccounts, error)
	DeleteServiceAccount(ctx context.Context, in *apiv1.AccountId, opts ...grpc.CallOption) (*emptypb.Empty, error)
	DeleteProvisionerAccount(ctx context.Context, in *apiv1.AccountId, opts ...grpc.CallOption) (*emptypb.Empty, error)
	DeleteProvisionedServiceAccount(ctx context.Context, in *apiv1.AccountId, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

func NewClient(endpoint string, attestation string, opts ...ClientOptions) (*Client, error) {
	var creds credentials.TransportCredentials

	c := Client{
		Endpoint:       endpoint,
		Attestation:    attestation,
		Authentication: Authentication{},
		Insecure:       false,
	}

	if len(opts) > 0 {
		err := c.ApplyOptions(opts...)
		if err != nil {
			return nil, err
		}
	}

	if c.Insecure {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})
	}

	conn, err := grpc.Dial(
		endpoint, grpc.WithTransportCredentials(creds),
		grpc.WithUnaryInterceptor(c.methodInterceptor()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize grpc client %w", err)
	}

	c.Certificate = apiv1.NewCertificateClient(conn)
	c.Service = apiv1.NewServiceClient(conn)
	c.Account = apiv1.NewAccountClient(conn)

	return &c, nil
}

func (c *Client) methodInterceptor() grpc.UnaryClientInterceptor {
	methodOptions := map[string]grpc.UnaryClientInterceptor{
		// Certificate Interface
		"/baseca.v1.Certificate/SignCSR":                  c.clientAuthUnaryInterceptor,
		"/baseca.v1.Certificate/OperationsSignCSR":        c.clientAuthUnaryInterceptor,
		"/baseca.v1.Certificate/QueryCertificateMetadata": c.clientAuthUnaryInterceptor,

		// Service Interface
		"/baseca.v1.Service/ProvisionServiceAccount":         c.clientAuthUnaryInterceptor,
		"/baseca.v1.Service/GetServiceAccountByMetadata":     c.clientAuthUnaryInterceptor,
		"/baseca.v1.Service/DeleteProvisionedServiceAccount": c.clientAuthUnaryInterceptor,

		// Account Interface
		"/baseca.v1.Account/LoginUser": c.accountAuthUnaryInterceptor,
	}
	return mapMethodInterceptor(methodOptions)
}

func mapMethodInterceptor(chain map[string]grpc.UnaryClientInterceptor) grpc.UnaryClientInterceptor {
	var chainMap sync.Map
	for k, v := range chain {
		chainMap.Store(k, v)
	}
	return func(parentCtx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if next, ok := returnMethodInterceptor(chainMap, method); ok {
			return next(parentCtx, method, req, reply, cc, invoker, opts...)
		}
		return invoker(parentCtx, method, req, reply, cc, opts...)
	}
}

func returnMethodInterceptor(chainMap sync.Map, method string) (grpc.UnaryClientInterceptor, bool) {
	if m, ok := chainMap.Load(method); ok {
		return m.(grpc.UnaryClientInterceptor), true
	}
	i := strings.LastIndex(method, "/")
	if m, ok := chainMap.Load(method[:i+1]); ok {
		return m.(grpc.UnaryClientInterceptor), true
	}
	if m, ok := chainMap.Load(""); ok {
		return m.(grpc.UnaryClientInterceptor), true
	}
	return nil, false
}

func (c *Client) clientAuthUnaryInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	ctx = metadata.AppendToOutgoingContext(ctx, _client_id_header, c.Authentication.ClientId)
	ctx = metadata.AppendToOutgoingContext(ctx, _client_token_header, c.Authentication.ClientToken)

	if c.Attestation == Attestation.AWS {
		instance_metadata, err := globalIIDCache.Get()
		if err != nil {
			return fmt.Errorf("error generating aws_iid node attestation: %w", err)
		}
		ctx = metadata.AppendToOutgoingContext(ctx, _aws_iid_metadata, instance_metadata)
	}

	err := invoker(ctx, method, req, reply, cc, opts...)
	return err
}

func (c *Client) accountAuthUnaryInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	ctx = metadata.AppendToOutgoingContext(ctx, _account_auth_header, fmt.Sprintf("Bearer %s", c.Authentication.AuthToken))

	err := invoker(ctx, method, req, reply, cc, opts...)
	return err
}

// We cache this globally in case multiple clients are instantiated: they
// share the cache. They will all have the same IID based on the EC2 instance
// they're running on.
var globalIIDCache = &iidCache{}

func (cache *iidCache) Get() (string, error) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	// If we have a cached value and it hasn't expired, use it.
	if cache.value != "" && cache.expiration.After(time.Now()) {
		return cache.value, nil
	}

	// We have no cache or the cache has expired, so refresh it and return that.
	instance_metadata, err := aws_iid.BuildInstanceMetadata()
	if err != nil {
		return "", fmt.Errorf("aws_iid.BuildInstanceMetadata failed: %w", err)
	}

	if instance_metadata == nil {
		return "", fmt.Errorf("got nil IID")
	}

	cache.value = *instance_metadata
	cache.expiration = time.Now().Add(iidCacheExpiration)
	return cache.value, nil
}

func (c *Client) ApplyOptions(options ...ClientOptions) error {
	for _, option := range options {
		if err := option(c); err != nil {
			return err
		}
	}
	return nil
}

func WithClientId(clientId string) ClientOptions {
	return func(c *Client) error {
		c.Authentication.ClientId = clientId
		return nil
	}
}

func WithClientToken(clientToken string) ClientOptions {
	return func(c *Client) error {
		c.Authentication.ClientToken = clientToken
		return nil
	}
}

func WithInsecure() ClientOptions {
	return func(c *Client) error {
		c.Insecure = true
		return nil
	}
}
