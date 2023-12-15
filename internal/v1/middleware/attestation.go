package middleware

import (
	"context"
	"encoding/json"

	"github.com/coinbase/baseca/internal/attestation/aws_iid"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/types"
	iid "github.com/coinbase/baseca/pkg/attestor/aws_iid"
	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type Credentials struct {
	ClientId    uuid.UUID
	ClientToken string
}

func (m *Middleware) attestNode(ctx context.Context, node types.NodeIIDAttestation, attestations []string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Internal, "failed to retrieve metadata from context")
	}

	for _, node_attestation := range attestations {
		clientIdentityDocumentHeader, ok := md[clientIdentityDocumentHeaderKey]
		if !ok {
			return status.Errorf(codes.InvalidArgument, "authorization header not provided")
		}

		aws_iid_metadata_bytes := []byte(clientIdentityDocumentHeader[0])
		instance_metadata := iid.EC2InstanceMetadata{}

		err := json.Unmarshal(aws_iid_metadata_bytes, &instance_metadata)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "error unmarshal aws_instance metadata")
		}

		switch node_attestation {
		// EC2 Instance Identity Document Attestation
		case types.AWS_IID.String():
			node.EC2InstanceMetadata = instance_metadata
			attestation_err := aws_iid.AWSIidNodeAttestation(node, m.cache)
			if attestation_err != nil {
				return logger.RpcError(status.Error(codes.Unauthenticated, "aws_iid attestation error"), attestation_err)
			}
		}
	}
	return nil
}

func extractRequestMetadata(ctx context.Context) (*Credentials, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Internal, "failed to retrieve metadata from context")
	}

	clientIdAuthorizationHeader, ok := md[clientIdAuthorizationHeaderKey]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
	}

	clientTokenAuthorizationHeader, ok := md[clientTokenAuthorizationHeaderKey]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "authorization header not provided")
	}

	client_uuid, err := uuid.Parse(clientIdAuthorizationHeader[0])
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid authorization header")
	}

	return &Credentials{
		ClientId:    client_uuid,
		ClientToken: clientTokenAuthorizationHeader[0],
	}, nil
}
