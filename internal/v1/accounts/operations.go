package accounts

import (
	"context"

	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/gogo/status"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Service) DeleteServiceAccount(ctx context.Context, req *apiv1.ServiceAccountId) (*emptypb.Empty, error) {
	client_id, err := uuid.Parse(req.Uuid)
	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.InvalidArgument, "invalid uuid parameter"), err)
	}

	err = s.store.Writer.TxDeleteServiceAccount(ctx, client_id)
	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return &emptypb.Empty{}, nil
}
