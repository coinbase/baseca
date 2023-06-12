package users

import (
	"context"
	"database/sql"
	"fmt"

	db "github.com/coinbase/baseca/db/sqlc"
	apiv1 "github.com/coinbase/baseca/gen/go/baseca/v1"
	"github.com/coinbase/baseca/internal/authentication"
	"github.com/coinbase/baseca/internal/authorization"
	"github.com/coinbase/baseca/internal/logger"
	"github.com/coinbase/baseca/internal/validator"
	"github.com/gogo/status"
	"github.com/google/uuid"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	MIN_ENTROPY_BITS                 = 60
	_default_authentication_duration = 15
)

func (u *User) LoginUser(ctx context.Context, req *apiv1.LoginUserRequest) (*apiv1.LoginUserResponse, error) {
	user, err := u.store.Reader.GetUser(ctx, req.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, logger.RpcError(status.Error(codes.NotFound, "user not found"), err)
		}
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), err)
	}

	if err := authentication.CheckPassword(req.Password, user.HashedCredential); err != nil {
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), err)
	}

	validity := func() int64 {
		if u.validity == 0 {
			return _default_authentication_duration
		}
		return int64(u.validity)
	}()

	accessToken, err := u.auth.Issue(ctx, authentication.ClaimProps{
		Subject:         user.Uuid,
		Permission:      user.Permissions,
		ValidForMinutes: validity,
	})
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication failed"), err)
	}

	response := apiv1.LoginUserResponse{
		AccessToken: *accessToken,
		User: &apiv1.User{
			Uuid:                user.Uuid.String(),
			Username:            user.Username,
			FullName:            user.FullName,
			Email:               user.Email,
			Permissions:         user.Permissions,
			CredentialChangedAt: timestamppb.New(user.CredentialChangedAt),
			CreatedAt:           timestamppb.New(user.CreatedAt)},
	}
	return &response, nil
}

func (u *User) CreateUser(ctx context.Context, req *apiv1.CreateUserRequest) (*apiv1.User, error) {
	if !authorization.IsSupportedPermission(req.Permissions) {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid permission field"), fmt.Errorf("invalid permission %s", req.Permissions))
	}

	err := passwordvalidator.Validate(req.Password, MIN_ENTROPY_BITS)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "minimum password strength requirement not met"), err)
	}

	hashedCredential, err := authentication.HashPassword(req.Password)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Unauthenticated, "authentication error"), err)
	}

	if !validator.ValidateEmail(req.Email) {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid email"), fmt.Errorf("invalid email %s", req.Email))
	}

	if len(req.Username) == 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid username"), fmt.Errorf("invalid username [%s]", req.Username))
	}

	if _, err = u.store.Reader.GetUser(ctx, req.Username); err != sql.ErrNoRows {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid username"), fmt.Errorf("user exists %s", req.Username))
	}

	user_uuid, err := uuid.NewRandom()
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	arg := db.CreateUserParams{
		Uuid:             user_uuid,
		Username:         req.Username,
		HashedCredential: hashedCredential,
		FullName:         req.FullName,
		Email:            req.Email,
		Permissions:      req.Permissions,
	}

	user, err := u.store.Writer.CreateUser(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return &apiv1.User{
		Uuid:                user.Uuid.String(),
		Username:            user.Username,
		FullName:            user.FullName,
		Email:               user.Email,
		Permissions:         user.Permissions,
		CredentialChangedAt: timestamppb.New(user.CredentialChangedAt),
		CreatedAt:           timestamppb.New(user.CreatedAt)}, nil
}

func (u *User) DeleteUser(ctx context.Context, req *apiv1.UsernameRequest) (*emptypb.Empty, error) {
	if len(req.Username) == 0 {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.InvalidArgument, "invalid argument"), fmt.Errorf("v1.Accounts/DeleteUser invalid argument"))
	}

	err := u.store.Writer.DeleteUser(ctx, req.Username)
	if err != nil {
		return &emptypb.Empty{}, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}
	return &emptypb.Empty{}, nil
}

func (u *User) GetUser(ctx context.Context, req *apiv1.UsernameRequest) (*apiv1.User, error) {
	if len(req.Username) == 0 {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), fmt.Errorf("v1.Accounts/GetUser invalid argument"))
	}

	user, err := u.store.Reader.GetUser(ctx, req.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, logger.RpcError(status.Error(codes.NotFound, "user not found"), err)
		}
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return &apiv1.User{
		Uuid:                user.Uuid.String(),
		Username:            user.Username,
		FullName:            user.FullName,
		Email:               user.Email,
		Permissions:         user.Permissions,
		CredentialChangedAt: timestamppb.New(user.CredentialChangedAt),
		CreatedAt:           timestamppb.New(user.CreatedAt)}, nil
}

func (u *User) ListUsers(ctx context.Context, req *apiv1.QueryParameter) (*apiv1.Users, error) {
	var userData apiv1.Users

	if req.PageId <= 0 || req.PageSize <= 0 {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid request parameters"), fmt.Errorf("invalid page_id or page_size"))
	}

	arg := db.ListUsersParams{
		Limit:  req.PageSize,
		Offset: (req.PageId - 1) * req.PageSize,
	}
	users, err := u.store.Reader.ListUsers(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid request"), err)
	}

	for _, user := range users {
		userData.Users = append(userData.Users, &apiv1.User{
			Uuid:                user.Uuid.String(),
			Username:            user.Username,
			FullName:            user.FullName,
			Email:               user.Email,
			Permissions:         user.Permissions,
			CredentialChangedAt: timestamppb.New(user.CredentialChangedAt),
			CreatedAt:           timestamppb.New(user.CreatedAt)})
	}
	return &userData, nil
}

func (u *User) UpdateUserPermissions(ctx context.Context, req *apiv1.UpdatePermissionsRequest) (*apiv1.User, error) {
	if !authorization.IsSupportedPermission(req.Permissions) {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "invalid permission field"), fmt.Errorf("invalid permission %s", req.Permissions))
	}

	arg := db.UpdateUserPermissionParams{
		Username:    req.Username,
		Permissions: req.Permissions,
	}

	user, err := u.store.Writer.UpdateUserPermission(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return &apiv1.User{
		Uuid:                user.Uuid.String(),
		Username:            user.Username,
		FullName:            user.FullName,
		Email:               user.Email,
		Permissions:         user.Permissions,
		CredentialChangedAt: timestamppb.New(user.CredentialChangedAt),
		CreatedAt:           timestamppb.New(user.CreatedAt)}, nil
}

func (u *User) UpdateUserCredentials(ctx context.Context, req *apiv1.UpdateCredentialsRequest) (*apiv1.User, error) {
	user, err := u.store.Reader.GetUser(ctx, req.Username)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	if err := authentication.CheckPassword(req.Password, user.HashedCredential); err != nil {
		return nil, logger.RpcError(status.Error(codes.PermissionDenied, "authentication failed"), err)
	}

	err = passwordvalidator.Validate(req.UpdatedPassword, MIN_ENTROPY_BITS)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.InvalidArgument, "minimum password strength requirement not met"), err)
	}

	hashedCredential, err := authentication.HashPassword(req.UpdatedPassword)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	arg := db.UpdateUserAuthenticationParams{
		Username:         req.Username,
		HashedCredential: hashedCredential,
	}

	user, err = u.store.Writer.UpdateUserAuthentication(ctx, arg)
	if err != nil {
		return nil, logger.RpcError(status.Error(codes.Internal, "internal server error"), err)
	}

	return &apiv1.User{
		Username:            user.Username,
		FullName:            user.FullName,
		Email:               user.Email,
		Permissions:         user.Permissions,
		CredentialChangedAt: timestamppb.New(user.CredentialChangedAt),
		CreatedAt:           timestamppb.New(user.CreatedAt)}, nil
}
