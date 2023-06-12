package baseca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/pkg/attestor/aws_iid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// var Endpoints Environment

var Attestation Provider = Provider{
	Local: "NONE",
	AWS:   "AWS",
}

var Env = Environment{
	Local:         "Local",
	Sandbox:       "Sandbox",
	Development:   "Development",
	Staging:       "Staging",
	PreProduction: "PreProduction",
	Production:    "Production",
}

type Environment struct {
	Local         string
	Sandbox       string
	Development   string
	Staging       string
	PreProduction string
	Production    string
}

type Configuration struct {
	URL         string
	Environment string
}

type Provider struct {
	Local string
	AWS   string
}

type Output struct {
	CertificateSigningRequest string
	Certificate               string
	CertificateChain          string
	PrivateKey                string
}
type CertificateRequest struct {
	CommonName            string
	SubjectAlternateNames []string
	DistinguishedName     DistinguishedName
	SigningAlgorithm      x509.SignatureAlgorithm
	PublicKeyAlgorithm    x509.PublicKeyAlgorithm
	KeySize               int
	Output                Output
}

type DistinguishedName struct {
	Country            []string
	Province           []string
	Locality           []string
	Organization       []string
	OrganizationalUnit []string
}

type Authentication struct {
	ClientId    string
	ClientToken string
}

type client struct {
	endpoint       string
	authentication Authentication
	attestation    string
	Certificate    apiv1.CertificateClient
}

const (
	_client_id_header    = "X-BASECA-CLIENT-ID"
	_client_token_header = "X-BASECA-CLIENT-TOKEN" // #nosec G101 False Positive
	_aws_iid_metadata    = "X-BASECA-INSTANCE-METADATA"
)

type CertificateClient interface {
	SignCSR(ctx context.Context, in *apiv1.CertificateSigningRequest, opts ...grpc.CallOption) (*apiv1.SignedCertificate, error)
}

func LoadDefaultConfiguration(configuration Configuration, client_id, client_token, attestation string) (*client, error) {
	c := client{
		endpoint:       configuration.URL,
		authentication: Authentication{client_id, client_token},
		attestation:    attestation,
	}

	if configuration.Environment == Env.Local {
		conn, err := grpc.Dial(configuration.URL, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(c.methodInterceptor()))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize grpc client")
		}
		c.Certificate = apiv1.NewCertificateClient(conn)
		return &c, nil
	} else {
		conn, err := grpc.Dial(configuration.URL, grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{
				MinVersion: tls.VersionTLS12,
			}),
		), grpc.WithUnaryInterceptor(c.methodInterceptor()))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize grpc client")
		}
		c.Certificate = apiv1.NewCertificateClient(conn)
		return &c, nil
	}
}

func (c *client) methodInterceptor() grpc.UnaryClientInterceptor {
	methodOptions := map[string]grpc.UnaryClientInterceptor{
		"/baseca.v1.Certificate/SignCSR":             c.clientAuthUnaryInterceptor,
		"/baseca.v1.Certificate/OperationsSignCSR":   c.clientAuthUnaryInterceptor,
		"/baseca.v1.Service/ProvisionServiceAccount": c.clientAuthUnaryInterceptor,
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

func (c *client) clientAuthUnaryInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	ctx = metadata.AppendToOutgoingContext(ctx, _client_id_header, c.authentication.ClientId)
	ctx = metadata.AppendToOutgoingContext(ctx, _client_token_header, c.authentication.ClientToken)

	if c.attestation == Attestation.AWS {
		instance_metadata, err := aws_iid.BuildInstanceMetadata()
		if err != nil {
			return fmt.Errorf("error generating aws_iid node attestation")
		}
		ctx = metadata.AppendToOutgoingContext(ctx, _aws_iid_metadata, *instance_metadata)
	}

	err := invoker(ctx, method, req, reply, cc, opts...)
	return err
}
