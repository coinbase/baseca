// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             (unknown)
// source: baseca/v1/api.proto

package apiv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// CertificateClient is the client API for Certificate service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CertificateClient interface {
	SignCSR(ctx context.Context, in *CertificateSigningRequest, opts ...grpc.CallOption) (*SignedCertificate, error)
	GetCertificate(ctx context.Context, in *CertificateSerialNumber, opts ...grpc.CallOption) (*CertificateParameter, error)
	ListCertificates(ctx context.Context, in *ListCertificatesRequest, opts ...grpc.CallOption) (*CertificatesParameter, error)
	RevokeCertificate(ctx context.Context, in *RevokeCertificateRequest, opts ...grpc.CallOption) (*RevokeCertificateResponse, error)
	OperationsSignCSR(ctx context.Context, in *OperationsSignRequest, opts ...grpc.CallOption) (*SignedCertificate, error)
}

type certificateClient struct {
	cc grpc.ClientConnInterface
}

func NewCertificateClient(cc grpc.ClientConnInterface) CertificateClient {
	return &certificateClient{cc}
}

func (c *certificateClient) SignCSR(ctx context.Context, in *CertificateSigningRequest, opts ...grpc.CallOption) (*SignedCertificate, error) {
	out := new(SignedCertificate)
	err := c.cc.Invoke(ctx, "/baseca.v1.Certificate/SignCSR", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certificateClient) GetCertificate(ctx context.Context, in *CertificateSerialNumber, opts ...grpc.CallOption) (*CertificateParameter, error) {
	out := new(CertificateParameter)
	err := c.cc.Invoke(ctx, "/baseca.v1.Certificate/GetCertificate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certificateClient) ListCertificates(ctx context.Context, in *ListCertificatesRequest, opts ...grpc.CallOption) (*CertificatesParameter, error) {
	out := new(CertificatesParameter)
	err := c.cc.Invoke(ctx, "/baseca.v1.Certificate/ListCertificates", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certificateClient) RevokeCertificate(ctx context.Context, in *RevokeCertificateRequest, opts ...grpc.CallOption) (*RevokeCertificateResponse, error) {
	out := new(RevokeCertificateResponse)
	err := c.cc.Invoke(ctx, "/baseca.v1.Certificate/RevokeCertificate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certificateClient) OperationsSignCSR(ctx context.Context, in *OperationsSignRequest, opts ...grpc.CallOption) (*SignedCertificate, error) {
	out := new(SignedCertificate)
	err := c.cc.Invoke(ctx, "/baseca.v1.Certificate/OperationsSignCSR", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CertificateServer is the server API for Certificate service.
// All implementations must embed UnimplementedCertificateServer
// for forward compatibility
type CertificateServer interface {
	SignCSR(context.Context, *CertificateSigningRequest) (*SignedCertificate, error)
	GetCertificate(context.Context, *CertificateSerialNumber) (*CertificateParameter, error)
	ListCertificates(context.Context, *ListCertificatesRequest) (*CertificatesParameter, error)
	RevokeCertificate(context.Context, *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
	OperationsSignCSR(context.Context, *OperationsSignRequest) (*SignedCertificate, error)
	mustEmbedUnimplementedCertificateServer()
}

// UnimplementedCertificateServer must be embedded to have forward compatible implementations.
type UnimplementedCertificateServer struct {
}

func (UnimplementedCertificateServer) SignCSR(context.Context, *CertificateSigningRequest) (*SignedCertificate, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignCSR not implemented")
}
func (UnimplementedCertificateServer) GetCertificate(context.Context, *CertificateSerialNumber) (*CertificateParameter, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCertificate not implemented")
}
func (UnimplementedCertificateServer) ListCertificates(context.Context, *ListCertificatesRequest) (*CertificatesParameter, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListCertificates not implemented")
}
func (UnimplementedCertificateServer) RevokeCertificate(context.Context, *RevokeCertificateRequest) (*RevokeCertificateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RevokeCertificate not implemented")
}
func (UnimplementedCertificateServer) OperationsSignCSR(context.Context, *OperationsSignRequest) (*SignedCertificate, error) {
	return nil, status.Errorf(codes.Unimplemented, "method OperationsSignCSR not implemented")
}
func (UnimplementedCertificateServer) mustEmbedUnimplementedCertificateServer() {}

// UnsafeCertificateServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CertificateServer will
// result in compilation errors.
type UnsafeCertificateServer interface {
	mustEmbedUnimplementedCertificateServer()
}

func RegisterCertificateServer(s grpc.ServiceRegistrar, srv CertificateServer) {
	s.RegisterService(&Certificate_ServiceDesc, srv)
}

func _Certificate_SignCSR_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CertificateSigningRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertificateServer).SignCSR(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Certificate/SignCSR",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertificateServer).SignCSR(ctx, req.(*CertificateSigningRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Certificate_GetCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CertificateSerialNumber)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertificateServer).GetCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Certificate/GetCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertificateServer).GetCertificate(ctx, req.(*CertificateSerialNumber))
	}
	return interceptor(ctx, in, info, handler)
}

func _Certificate_ListCertificates_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListCertificatesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertificateServer).ListCertificates(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Certificate/ListCertificates",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertificateServer).ListCertificates(ctx, req.(*ListCertificatesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Certificate_RevokeCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertificateServer).RevokeCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Certificate/RevokeCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertificateServer).RevokeCertificate(ctx, req.(*RevokeCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Certificate_OperationsSignCSR_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OperationsSignRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertificateServer).OperationsSignCSR(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Certificate/OperationsSignCSR",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertificateServer).OperationsSignCSR(ctx, req.(*OperationsSignRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Certificate_ServiceDesc is the grpc.ServiceDesc for Certificate service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Certificate_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "baseca.v1.Certificate",
	HandlerType: (*CertificateServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignCSR",
			Handler:    _Certificate_SignCSR_Handler,
		},
		{
			MethodName: "GetCertificate",
			Handler:    _Certificate_GetCertificate_Handler,
		},
		{
			MethodName: "ListCertificates",
			Handler:    _Certificate_ListCertificates_Handler,
		},
		{
			MethodName: "RevokeCertificate",
			Handler:    _Certificate_RevokeCertificate_Handler,
		},
		{
			MethodName: "OperationsSignCSR",
			Handler:    _Certificate_OperationsSignCSR_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "baseca/v1/api.proto",
}

// AccountClient is the client API for Account service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AccountClient interface {
	LoginUser(ctx context.Context, in *LoginUserRequest, opts ...grpc.CallOption) (*LoginUserResponse, error)
	DeleteUser(ctx context.Context, in *UsernameRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	GetUser(ctx context.Context, in *UsernameRequest, opts ...grpc.CallOption) (*User, error)
	ListUsers(ctx context.Context, in *QueryParameter, opts ...grpc.CallOption) (*Users, error)
	CreateUser(ctx context.Context, in *CreateUserRequest, opts ...grpc.CallOption) (*User, error)
	UpdateUserCredentials(ctx context.Context, in *UpdateCredentialsRequest, opts ...grpc.CallOption) (*User, error)
	UpdateUserPermissions(ctx context.Context, in *UpdatePermissionsRequest, opts ...grpc.CallOption) (*User, error)
}

type accountClient struct {
	cc grpc.ClientConnInterface
}

func NewAccountClient(cc grpc.ClientConnInterface) AccountClient {
	return &accountClient{cc}
}

func (c *accountClient) LoginUser(ctx context.Context, in *LoginUserRequest, opts ...grpc.CallOption) (*LoginUserResponse, error) {
	out := new(LoginUserResponse)
	err := c.cc.Invoke(ctx, "/baseca.v1.Account/LoginUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) DeleteUser(ctx context.Context, in *UsernameRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, "/baseca.v1.Account/DeleteUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) GetUser(ctx context.Context, in *UsernameRequest, opts ...grpc.CallOption) (*User, error) {
	out := new(User)
	err := c.cc.Invoke(ctx, "/baseca.v1.Account/GetUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) ListUsers(ctx context.Context, in *QueryParameter, opts ...grpc.CallOption) (*Users, error) {
	out := new(Users)
	err := c.cc.Invoke(ctx, "/baseca.v1.Account/ListUsers", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) CreateUser(ctx context.Context, in *CreateUserRequest, opts ...grpc.CallOption) (*User, error) {
	out := new(User)
	err := c.cc.Invoke(ctx, "/baseca.v1.Account/CreateUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) UpdateUserCredentials(ctx context.Context, in *UpdateCredentialsRequest, opts ...grpc.CallOption) (*User, error) {
	out := new(User)
	err := c.cc.Invoke(ctx, "/baseca.v1.Account/UpdateUserCredentials", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) UpdateUserPermissions(ctx context.Context, in *UpdatePermissionsRequest, opts ...grpc.CallOption) (*User, error) {
	out := new(User)
	err := c.cc.Invoke(ctx, "/baseca.v1.Account/UpdateUserPermissions", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AccountServer is the server API for Account service.
// All implementations must embed UnimplementedAccountServer
// for forward compatibility
type AccountServer interface {
	LoginUser(context.Context, *LoginUserRequest) (*LoginUserResponse, error)
	DeleteUser(context.Context, *UsernameRequest) (*emptypb.Empty, error)
	GetUser(context.Context, *UsernameRequest) (*User, error)
	ListUsers(context.Context, *QueryParameter) (*Users, error)
	CreateUser(context.Context, *CreateUserRequest) (*User, error)
	UpdateUserCredentials(context.Context, *UpdateCredentialsRequest) (*User, error)
	UpdateUserPermissions(context.Context, *UpdatePermissionsRequest) (*User, error)
	mustEmbedUnimplementedAccountServer()
}

// UnimplementedAccountServer must be embedded to have forward compatible implementations.
type UnimplementedAccountServer struct {
}

func (UnimplementedAccountServer) LoginUser(context.Context, *LoginUserRequest) (*LoginUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LoginUser not implemented")
}
func (UnimplementedAccountServer) DeleteUser(context.Context, *UsernameRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUser not implemented")
}
func (UnimplementedAccountServer) GetUser(context.Context, *UsernameRequest) (*User, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUser not implemented")
}
func (UnimplementedAccountServer) ListUsers(context.Context, *QueryParameter) (*Users, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers not implemented")
}
func (UnimplementedAccountServer) CreateUser(context.Context, *CreateUserRequest) (*User, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser not implemented")
}
func (UnimplementedAccountServer) UpdateUserCredentials(context.Context, *UpdateCredentialsRequest) (*User, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUserCredentials not implemented")
}
func (UnimplementedAccountServer) UpdateUserPermissions(context.Context, *UpdatePermissionsRequest) (*User, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUserPermissions not implemented")
}
func (UnimplementedAccountServer) mustEmbedUnimplementedAccountServer() {}

// UnsafeAccountServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AccountServer will
// result in compilation errors.
type UnsafeAccountServer interface {
	mustEmbedUnimplementedAccountServer()
}

func RegisterAccountServer(s grpc.ServiceRegistrar, srv AccountServer) {
	s.RegisterService(&Account_ServiceDesc, srv)
}

func _Account_LoginUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).LoginUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Account/LoginUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).LoginUser(ctx, req.(*LoginUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_DeleteUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UsernameRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).DeleteUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Account/DeleteUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).DeleteUser(ctx, req.(*UsernameRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_GetUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UsernameRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).GetUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Account/GetUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).GetUser(ctx, req.(*UsernameRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_ListUsers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryParameter)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).ListUsers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Account/ListUsers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).ListUsers(ctx, req.(*QueryParameter))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_CreateUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).CreateUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Account/CreateUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).CreateUser(ctx, req.(*CreateUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_UpdateUserCredentials_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateCredentialsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).UpdateUserCredentials(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Account/UpdateUserCredentials",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).UpdateUserCredentials(ctx, req.(*UpdateCredentialsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_UpdateUserPermissions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdatePermissionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).UpdateUserPermissions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Account/UpdateUserPermissions",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).UpdateUserPermissions(ctx, req.(*UpdatePermissionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Account_ServiceDesc is the grpc.ServiceDesc for Account service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Account_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "baseca.v1.Account",
	HandlerType: (*AccountServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "LoginUser",
			Handler:    _Account_LoginUser_Handler,
		},
		{
			MethodName: "DeleteUser",
			Handler:    _Account_DeleteUser_Handler,
		},
		{
			MethodName: "GetUser",
			Handler:    _Account_GetUser_Handler,
		},
		{
			MethodName: "ListUsers",
			Handler:    _Account_ListUsers_Handler,
		},
		{
			MethodName: "CreateUser",
			Handler:    _Account_CreateUser_Handler,
		},
		{
			MethodName: "UpdateUserCredentials",
			Handler:    _Account_UpdateUserCredentials_Handler,
		},
		{
			MethodName: "UpdateUserPermissions",
			Handler:    _Account_UpdateUserPermissions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "baseca/v1/api.proto",
}

// ServiceClient is the client API for Service service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ServiceClient interface {
	CreateServiceAccount(ctx context.Context, in *CreateServiceAccountRequest, opts ...grpc.CallOption) (*CreateServiceAccountResponse, error)
	ProvisionServiceAccount(ctx context.Context, in *ProvisionServiceAccountRequest, opts ...grpc.CallOption) (*ProvisionServiceAccountResponse, error)
	ListServiceAccounts(ctx context.Context, in *QueryParameter, opts ...grpc.CallOption) (*ServiceAccounts, error)
	GetServiceAccountUuid(ctx context.Context, in *ServiceAccountId, opts ...grpc.CallOption) (*ServiceAccount, error)
	GetServiceAccountName(ctx context.Context, in *ServiceAccountName, opts ...grpc.CallOption) (*ServiceAccounts, error)
	DeleteServiceAccount(ctx context.Context, in *ServiceAccountId, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type serviceClient struct {
	cc grpc.ClientConnInterface
}

func NewServiceClient(cc grpc.ClientConnInterface) ServiceClient {
	return &serviceClient{cc}
}

func (c *serviceClient) CreateServiceAccount(ctx context.Context, in *CreateServiceAccountRequest, opts ...grpc.CallOption) (*CreateServiceAccountResponse, error) {
	out := new(CreateServiceAccountResponse)
	err := c.cc.Invoke(ctx, "/baseca.v1.Service/CreateServiceAccount", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) ProvisionServiceAccount(ctx context.Context, in *ProvisionServiceAccountRequest, opts ...grpc.CallOption) (*ProvisionServiceAccountResponse, error) {
	out := new(ProvisionServiceAccountResponse)
	err := c.cc.Invoke(ctx, "/baseca.v1.Service/ProvisionServiceAccount", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) ListServiceAccounts(ctx context.Context, in *QueryParameter, opts ...grpc.CallOption) (*ServiceAccounts, error) {
	out := new(ServiceAccounts)
	err := c.cc.Invoke(ctx, "/baseca.v1.Service/ListServiceAccounts", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) GetServiceAccountUuid(ctx context.Context, in *ServiceAccountId, opts ...grpc.CallOption) (*ServiceAccount, error) {
	out := new(ServiceAccount)
	err := c.cc.Invoke(ctx, "/baseca.v1.Service/GetServiceAccountUuid", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) GetServiceAccountName(ctx context.Context, in *ServiceAccountName, opts ...grpc.CallOption) (*ServiceAccounts, error) {
	out := new(ServiceAccounts)
	err := c.cc.Invoke(ctx, "/baseca.v1.Service/GetServiceAccountName", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) DeleteServiceAccount(ctx context.Context, in *ServiceAccountId, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, "/baseca.v1.Service/DeleteServiceAccount", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ServiceServer is the server API for Service service.
// All implementations must embed UnimplementedServiceServer
// for forward compatibility
type ServiceServer interface {
	CreateServiceAccount(context.Context, *CreateServiceAccountRequest) (*CreateServiceAccountResponse, error)
	ProvisionServiceAccount(context.Context, *ProvisionServiceAccountRequest) (*ProvisionServiceAccountResponse, error)
	ListServiceAccounts(context.Context, *QueryParameter) (*ServiceAccounts, error)
	GetServiceAccountUuid(context.Context, *ServiceAccountId) (*ServiceAccount, error)
	GetServiceAccountName(context.Context, *ServiceAccountName) (*ServiceAccounts, error)
	DeleteServiceAccount(context.Context, *ServiceAccountId) (*emptypb.Empty, error)
	mustEmbedUnimplementedServiceServer()
}

// UnimplementedServiceServer must be embedded to have forward compatible implementations.
type UnimplementedServiceServer struct {
}

func (UnimplementedServiceServer) CreateServiceAccount(context.Context, *CreateServiceAccountRequest) (*CreateServiceAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateServiceAccount not implemented")
}
func (UnimplementedServiceServer) ProvisionServiceAccount(context.Context, *ProvisionServiceAccountRequest) (*ProvisionServiceAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ProvisionServiceAccount not implemented")
}
func (UnimplementedServiceServer) ListServiceAccounts(context.Context, *QueryParameter) (*ServiceAccounts, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListServiceAccounts not implemented")
}
func (UnimplementedServiceServer) GetServiceAccountUuid(context.Context, *ServiceAccountId) (*ServiceAccount, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetServiceAccountUuid not implemented")
}
func (UnimplementedServiceServer) GetServiceAccountName(context.Context, *ServiceAccountName) (*ServiceAccounts, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetServiceAccountName not implemented")
}
func (UnimplementedServiceServer) DeleteServiceAccount(context.Context, *ServiceAccountId) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteServiceAccount not implemented")
}
func (UnimplementedServiceServer) mustEmbedUnimplementedServiceServer() {}

// UnsafeServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ServiceServer will
// result in compilation errors.
type UnsafeServiceServer interface {
	mustEmbedUnimplementedServiceServer()
}

func RegisterServiceServer(s grpc.ServiceRegistrar, srv ServiceServer) {
	s.RegisterService(&Service_ServiceDesc, srv)
}

func _Service_CreateServiceAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateServiceAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceServer).CreateServiceAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Service/CreateServiceAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceServer).CreateServiceAccount(ctx, req.(*CreateServiceAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Service_ProvisionServiceAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProvisionServiceAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceServer).ProvisionServiceAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Service/ProvisionServiceAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceServer).ProvisionServiceAccount(ctx, req.(*ProvisionServiceAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Service_ListServiceAccounts_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryParameter)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceServer).ListServiceAccounts(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Service/ListServiceAccounts",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceServer).ListServiceAccounts(ctx, req.(*QueryParameter))
	}
	return interceptor(ctx, in, info, handler)
}

func _Service_GetServiceAccountUuid_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ServiceAccountId)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceServer).GetServiceAccountUuid(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Service/GetServiceAccountUuid",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceServer).GetServiceAccountUuid(ctx, req.(*ServiceAccountId))
	}
	return interceptor(ctx, in, info, handler)
}

func _Service_GetServiceAccountName_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ServiceAccountName)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceServer).GetServiceAccountName(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Service/GetServiceAccountName",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceServer).GetServiceAccountName(ctx, req.(*ServiceAccountName))
	}
	return interceptor(ctx, in, info, handler)
}

func _Service_DeleteServiceAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ServiceAccountId)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServiceServer).DeleteServiceAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Service/DeleteServiceAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServiceServer).DeleteServiceAccount(ctx, req.(*ServiceAccountId))
	}
	return interceptor(ctx, in, info, handler)
}

// Service_ServiceDesc is the grpc.ServiceDesc for Service service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Service_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "baseca.v1.Service",
	HandlerType: (*ServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateServiceAccount",
			Handler:    _Service_CreateServiceAccount_Handler,
		},
		{
			MethodName: "ProvisionServiceAccount",
			Handler:    _Service_ProvisionServiceAccount_Handler,
		},
		{
			MethodName: "ListServiceAccounts",
			Handler:    _Service_ListServiceAccounts_Handler,
		},
		{
			MethodName: "GetServiceAccountUuid",
			Handler:    _Service_GetServiceAccountUuid_Handler,
		},
		{
			MethodName: "GetServiceAccountName",
			Handler:    _Service_GetServiceAccountName_Handler,
		},
		{
			MethodName: "DeleteServiceAccount",
			Handler:    _Service_DeleteServiceAccount_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "baseca/v1/api.proto",
}

// HealthClient is the client API for Health service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type HealthClient interface {
	Check(ctx context.Context, in *HealthCheckRequest, opts ...grpc.CallOption) (*HealthCheckResponse, error)
}

type healthClient struct {
	cc grpc.ClientConnInterface
}

func NewHealthClient(cc grpc.ClientConnInterface) HealthClient {
	return &healthClient{cc}
}

func (c *healthClient) Check(ctx context.Context, in *HealthCheckRequest, opts ...grpc.CallOption) (*HealthCheckResponse, error) {
	out := new(HealthCheckResponse)
	err := c.cc.Invoke(ctx, "/baseca.v1.Health/Check", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HealthServer is the server API for Health service.
// All implementations must embed UnimplementedHealthServer
// for forward compatibility
type HealthServer interface {
	Check(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error)
	mustEmbedUnimplementedHealthServer()
}

// UnimplementedHealthServer must be embedded to have forward compatible implementations.
type UnimplementedHealthServer struct {
}

func (UnimplementedHealthServer) Check(context.Context, *HealthCheckRequest) (*HealthCheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Check not implemented")
}
func (UnimplementedHealthServer) mustEmbedUnimplementedHealthServer() {}

// UnsafeHealthServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to HealthServer will
// result in compilation errors.
type UnsafeHealthServer interface {
	mustEmbedUnimplementedHealthServer()
}

func RegisterHealthServer(s grpc.ServiceRegistrar, srv HealthServer) {
	s.RegisterService(&Health_ServiceDesc, srv)
}

func _Health_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HealthCheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HealthServer).Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/baseca.v1.Health/Check",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HealthServer).Check(ctx, req.(*HealthCheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Health_ServiceDesc is the grpc.ServiceDesc for Health service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Health_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "baseca.v1.Health",
	HandlerType: (*HealthServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Check",
			Handler:    _Health_Check_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "baseca/v1/api.proto",
}
