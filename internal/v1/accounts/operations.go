package accounts

import (
	"context"
	"fmt"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Service) DeleteServiceAccount(ctx context.Context, req *apiv1.AccountId) (*emptypb.Empty, error) {
	client_id, err := uuid.Parse(req.Uuid)
	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.InvalidArgument, "invalid uuid parameter"), fmt.Errorf("[DeleteServiceAccount] invalid UUID %s", req.Uuid))
	}

	err = s.store.Writer.TxDeleteServiceAccount(ctx, client_id)
	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.Internal, "internal server error"), fmt.Errorf("[DeleteServiceAccount] deletion transaction failed %s", err))
	}

	return &emptypb.Empty{}, nil
}

func (s *Service) DeleteProvisionerAccount(ctx context.Context, req *apiv1.AccountId) (*emptypb.Empty, error) {
	client_id, err := uuid.Parse(req.Uuid)
	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.InvalidArgument, "invalid uuid parameter"), fmt.Errorf("[DeleteProvisionerAccount] invalid UUID %s", req.Uuid))
	}

	err = s.store.Writer.TxDeleteProvisionerAccount(ctx, client_id)

	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.Internal, "internal server error"), fmt.Errorf("[DeleteProvisionerAccount] deletion transaction failed %s", err))
	}

	return &emptypb.Empty{}, nil
}
