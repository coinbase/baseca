package lib

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	config_v2 "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/coinbase/baseca/internal/config"
	"github.com/google/uuid"
)

type KmsClientIface interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

type signer struct {
	sign            func(ctx context.Context, message string) ([]byte, error)
	verifySignature func(ctx context.Context, message string, signature string) (bool, error)
	algorithm       func(ctx context.Context) string
	keyId           string
	time            func() time.Time
}

type ClaimProps struct {
	Subject         uuid.UUID
	Permission      string
	ValidForMinutes int64
}

type Client struct {
	KmsClient        KmsClientIface
	KeyId            string
	SigningAlgorithm string
}

type Header struct {
	Algorithm string
	Type      string
	KeyId     string
}

type Claims struct {
	Permission string    `json:"permission"`
	Subject    uuid.UUID `json:"sub"`
	IssuedAt   time.Time `json:"iss"`
	ExpiresAt  time.Time `json:"exp"`
	NotBefore  time.Time `json:"not_before"`
}

type Auth interface {
	Issue(context.Context, ClaimProps) (*string, error)
	Verify(context.Context, string) (*Claims, error)
}

var signingAlgorithms = map[string]types.SigningAlgorithmSpec{
	"RSASSA_PSS_SHA_256":        types.SigningAlgorithmSpecRsassaPssSha256,
	"RSASSA_PSS_SHA_384":        types.SigningAlgorithmSpecRsassaPssSha384,
	"RSASSA_PSS_SHA_512":        types.SigningAlgorithmSpecRsassaPssSha512,
	"RSASSA_PKCS1_V1_5_SHA_256": types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	"RSASSA_PKCS1_V1_5_SHA_384": types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
	"RSASSA_PKCS1_V1_5_SHA_512": types.SigningAlgorithmSpecEcdsaSha512,
}

func BuildSigningClient(config *config.Config) (*Client, error) {
	cfg, err := config_v2.LoadDefaultConfig(context.TODO(),
		config_v2.WithRegion(config.KMS.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("could not load kms configuration: %s", err)
	}

	return &Client{
		KmsClient:        kms.NewFromConfig(cfg),
		KeyId:            config.KMS.KeyId,
		SigningAlgorithm: config.KMS.SigningAlgorithm,
	}, nil
}

func NewAuthSigningMetadata(c *Client) (Auth, error) {
	s := &signer{
		sign: func(ctx context.Context, message string) ([]byte, error) {
			algorithm, ok := signingAlgorithms[c.SigningAlgorithm]
			if !ok {
				return nil, fmt.Errorf("signing algorithm mapping not supported: %s", c.SigningAlgorithm)
			}
			signInput := kms.SignInput{
				KeyId:            &c.KeyId,
				Message:          []byte(message),
				SigningAlgorithm: algorithm,
			}

			signOutput, err := c.KmsClient.Sign(ctx, &signInput)
			if err != nil {
				return nil, err
			}
			return signOutput.Signature, nil
		},
		verifySignature: func(ctx context.Context, b64Message string, b64Signature string) (bool, error) {
			decodedSignature, err := base64.RawURLEncoding.DecodeString(b64Signature)
			if err != nil {
				return false, fmt.Errorf("error decoding base64 signature: %s, error: %w", b64Signature, err)
			}

			algorithm, ok := signingAlgorithms[c.SigningAlgorithm]
			if !ok {
				return false, fmt.Errorf("signing algorithm mapping not supported: %s", c.SigningAlgorithm)
			}
			verifyInput := &kms.VerifyInput{
				KeyId:            &c.KeyId,
				Message:          []byte(b64Message),
				Signature:        decodedSignature,
				SigningAlgorithm: algorithm,
			}

			verifyOutput, err := c.KmsClient.Verify(ctx, verifyInput)
			if err != nil {
				return false, err
			}
			return verifyOutput.SignatureValid, nil
		},
		algorithm: func(ctx context.Context) string {
			return c.SigningAlgorithm
		},
		keyId: c.KeyId,
		time:  time.Now().UTC,
	}
	return s, nil
}

func (s *signer) Issue(ctx context.Context, p ClaimProps) (*string, error) {
	header := Header{
		Algorithm: s.algorithm(ctx),
		Type:      "JWT",
		KeyId:     s.keyId,
	}

	tokenJson, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("could not marshal token to json: %s", err)
	}

	headerStr := base64.RawURLEncoding.EncodeToString([]byte(tokenJson))
	claims := Claims{
		Permission: p.Permission,
		Subject:    p.Subject,
		IssuedAt:   time.Now().UTC(),
		NotBefore:  time.Now().UTC(),
		ExpiresAt:  time.Now().Add(time.Duration(p.ValidForMinutes * int64(time.Minute))).UTC(),
	}
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("could not marshal token claims to json: %s", err)
	}
	claimsStr := base64.RawURLEncoding.EncodeToString([]byte(claimsJson))

	message := fmt.Sprintf("%s.%s", headerStr, claimsStr)
	signatureBytes, err := s.sign(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("token signing error: %s", err)
	}

	signatureStr := base64.RawURLEncoding.EncodeToString(signatureBytes)
	tokenStr := fmt.Sprintf("%s.%s.%s", headerStr, claimsStr, signatureStr)
	return &tokenStr, nil
}

func (s *signer) Verify(ctx context.Context, jwt string) (*Claims, error) {
	x := strings.Split(jwt, ".")
	if len(x) != 3 {
		return nil, fmt.Errorf("invalid jwt format")
	}

	headerB64 := x[0]
	claimsB64 := x[1]
	signatureB64 := x[2]

	headerJson, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding header failed: %w", err)
	}

	header := &Header{}
	err = json.Unmarshal(headerJson, header)
	if err != nil {
		return nil, fmt.Errorf("json unmarshalling header failed: %v", err)
	}

	claimsJson, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding claims failed: %v", err)
	}

	claims := &Claims{}
	err = json.Unmarshal(claimsJson, claims)
	if err != nil {
		return nil, fmt.Errorf("json unmarshalling claims failed: %v", err)
	}

	err = claims.Valid()
	if err != nil {
		return nil, err
	}
	isVerified, err := s.verifySignature(ctx, fmt.Sprintf("%s.%s", x[0], x[1]), signatureB64)
	if err != nil {
		return nil, fmt.Errorf("error verifying signature: %v", err)
	}

	if !isVerified {
		return nil, err
	}
	return claims, nil
}

func (c *Claims) Valid() error {
	if time.Now().UTC().After(c.ExpiresAt) {
		return errors.New("token has expired")
	}

	if time.Now().UTC().Before(c.NotBefore) {
		return errors.New("token is invalid")
	}
	return nil
}
