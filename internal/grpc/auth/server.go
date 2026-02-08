package auth

import (
	"context"

	ssov1 "github.com/LearLocker/protoc/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appId int32,
	) (token string, err error)
	RegisterUser(
		ctx context.Context,
		email string,
		password string,
	) (userId int64, err error)
	IsAdmin(
		ctx context.Context,
		userId int64,
	) (isAdmin bool, err error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	err := validateLoginReq(req)
	if err != nil {
		return nil, err
	}

	// login via auth server
	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId())
	if err != nil {
		// TODO validate by error type
		return nil, status.Error(codes.Unauthenticated, "Internal error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	err := validateRegisterUserReq(req)
	if err != nil {
		return nil, err
	}

	userId, err := s.auth.RegisterUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		// TODO validate by error type
		return nil, status.Error(codes.Unauthenticated, "Internal error")
	}

	return &ssov1.RegisterResponse{
		UserId: userId,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	err := validateIsAdminReq(req)
	if err != nil {
		return nil, err
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		// TODO validate by error type
		return nil, status.Error(codes.PermissionDenied, "Internal error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func validateLoginReq(req *ssov1.LoginRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password required")
	}

	if req.GetAppId() == 0 {
		return status.Error(codes.InvalidArgument, "app id required")
	}

	return nil
}

func validateRegisterUserReq(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password required")
	}

	return nil
}

func validateIsAdminReq(req *ssov1.IsAdminRequest) error {
	if req.GetUserId() == 0 {
		return status.Error(codes.InvalidArgument, "user id required")
	}

	return nil
}
