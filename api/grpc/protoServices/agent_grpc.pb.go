// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.25.3
// source: agent.proto

package protoServices

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ConnectionClient is the client API for Connection service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ConnectionClient interface {
	Hello(ctx context.Context, in *SecurityToken, opts ...grpc.CallOption) (*SecurityToken, error)
}

type connectionClient struct {
	cc grpc.ClientConnInterface
}

func NewConnectionClient(cc grpc.ClientConnInterface) ConnectionClient {
	return &connectionClient{cc}
}

func (c *connectionClient) Hello(ctx context.Context, in *SecurityToken, opts ...grpc.CallOption) (*SecurityToken, error) {
	out := new(SecurityToken)
	err := c.cc.Invoke(ctx, "/contracts.Connection/Hello", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConnectionServer is the server API for Connection service.
// All implementations must embed UnimplementedConnectionServer
// for forward compatibility
type ConnectionServer interface {
	Hello(context.Context, *SecurityToken) (*SecurityToken, error)
	mustEmbedUnimplementedConnectionServer()
}

// UnimplementedConnectionServer must be embedded to have forward compatible implementations.
type UnimplementedConnectionServer struct {
}

func (UnimplementedConnectionServer) Hello(context.Context, *SecurityToken) (*SecurityToken, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Hello not implemented")
}
func (UnimplementedConnectionServer) mustEmbedUnimplementedConnectionServer() {}

// UnsafeConnectionServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ConnectionServer will
// result in compilation errors.
type UnsafeConnectionServer interface {
	mustEmbedUnimplementedConnectionServer()
}

func RegisterConnectionServer(s grpc.ServiceRegistrar, srv ConnectionServer) {
	s.RegisterService(&Connection_ServiceDesc, srv)
}

func _Connection_Hello_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SecurityToken)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConnectionServer).Hello(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Connection/Hello",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConnectionServer).Hello(ctx, req.(*SecurityToken))
	}
	return interceptor(ctx, in, info, handler)
}

// Connection_ServiceDesc is the grpc.ServiceDesc for Connection service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Connection_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "contracts.Connection",
	HandlerType: (*ConnectionServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Hello",
			Handler:    _Connection_Hello_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "agent.proto",
}

// JobsClient is the client API for Jobs service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type JobsClient interface {
	// StartJob accepts Job with all required params, streams back all queried and found results
	StartOSS(ctx context.Context, in *Job, opts ...grpc.CallOption) (Jobs_StartOSSClient, error)
	StartDNS(ctx context.Context, in *Job, opts ...grpc.CallOption) (Jobs_StartDNSClient, error)
	StartWHOIS(ctx context.Context, in *Job, opts ...grpc.CallOption) (Jobs_StartWHOISClient, error)
}

type jobsClient struct {
	cc grpc.ClientConnInterface
}

func NewJobsClient(cc grpc.ClientConnInterface) JobsClient {
	return &jobsClient{cc}
}

func (c *jobsClient) StartOSS(ctx context.Context, in *Job, opts ...grpc.CallOption) (Jobs_StartOSSClient, error) {
	stream, err := c.cc.NewStream(ctx, &Jobs_ServiceDesc.Streams[0], "/contracts.Jobs/StartOSS", opts...)
	if err != nil {
		return nil, err
	}
	x := &jobsStartOSSClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Jobs_StartOSSClient interface {
	Recv() (*TargetAuditReport, error)
	grpc.ClientStream
}

type jobsStartOSSClient struct {
	grpc.ClientStream
}

func (x *jobsStartOSSClient) Recv() (*TargetAuditReport, error) {
	m := new(TargetAuditReport)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *jobsClient) StartDNS(ctx context.Context, in *Job, opts ...grpc.CallOption) (Jobs_StartDNSClient, error) {
	stream, err := c.cc.NewStream(ctx, &Jobs_ServiceDesc.Streams[1], "/contracts.Jobs/StartDNS", opts...)
	if err != nil {
		return nil, err
	}
	x := &jobsStartDNSClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Jobs_StartDNSClient interface {
	Recv() (*TargetAuditReport, error)
	grpc.ClientStream
}

type jobsStartDNSClient struct {
	grpc.ClientStream
}

func (x *jobsStartDNSClient) Recv() (*TargetAuditReport, error) {
	m := new(TargetAuditReport)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *jobsClient) StartWHOIS(ctx context.Context, in *Job, opts ...grpc.CallOption) (Jobs_StartWHOISClient, error) {
	stream, err := c.cc.NewStream(ctx, &Jobs_ServiceDesc.Streams[2], "/contracts.Jobs/StartWHOIS", opts...)
	if err != nil {
		return nil, err
	}
	x := &jobsStartWHOISClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Jobs_StartWHOISClient interface {
	Recv() (*TargetAuditReport, error)
	grpc.ClientStream
}

type jobsStartWHOISClient struct {
	grpc.ClientStream
}

func (x *jobsStartWHOISClient) Recv() (*TargetAuditReport, error) {
	m := new(TargetAuditReport)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// JobsServer is the server API for Jobs service.
// All implementations must embed UnimplementedJobsServer
// for forward compatibility
type JobsServer interface {
	// StartJob accepts Job with all required params, streams back all queried and found results
	StartOSS(*Job, Jobs_StartOSSServer) error
	StartDNS(*Job, Jobs_StartDNSServer) error
	StartWHOIS(*Job, Jobs_StartWHOISServer) error
	mustEmbedUnimplementedJobsServer()
}

// UnimplementedJobsServer must be embedded to have forward compatible implementations.
type UnimplementedJobsServer struct {
}

func (UnimplementedJobsServer) StartOSS(*Job, Jobs_StartOSSServer) error {
	return status.Errorf(codes.Unimplemented, "method StartOSS not implemented")
}
func (UnimplementedJobsServer) StartDNS(*Job, Jobs_StartDNSServer) error {
	return status.Errorf(codes.Unimplemented, "method StartDNS not implemented")
}
func (UnimplementedJobsServer) StartWHOIS(*Job, Jobs_StartWHOISServer) error {
	return status.Errorf(codes.Unimplemented, "method StartWHOIS not implemented")
}
func (UnimplementedJobsServer) mustEmbedUnimplementedJobsServer() {}

// UnsafeJobsServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to JobsServer will
// result in compilation errors.
type UnsafeJobsServer interface {
	mustEmbedUnimplementedJobsServer()
}

func RegisterJobsServer(s grpc.ServiceRegistrar, srv JobsServer) {
	s.RegisterService(&Jobs_ServiceDesc, srv)
}

func _Jobs_StartOSS_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Job)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(JobsServer).StartOSS(m, &jobsStartOSSServer{stream})
}

type Jobs_StartOSSServer interface {
	Send(*TargetAuditReport) error
	grpc.ServerStream
}

type jobsStartOSSServer struct {
	grpc.ServerStream
}

func (x *jobsStartOSSServer) Send(m *TargetAuditReport) error {
	return x.ServerStream.SendMsg(m)
}

func _Jobs_StartDNS_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Job)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(JobsServer).StartDNS(m, &jobsStartDNSServer{stream})
}

type Jobs_StartDNSServer interface {
	Send(*TargetAuditReport) error
	grpc.ServerStream
}

type jobsStartDNSServer struct {
	grpc.ServerStream
}

func (x *jobsStartDNSServer) Send(m *TargetAuditReport) error {
	return x.ServerStream.SendMsg(m)
}

func _Jobs_StartWHOIS_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Job)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(JobsServer).StartWHOIS(m, &jobsStartWHOISServer{stream})
}

type Jobs_StartWHOISServer interface {
	Send(*TargetAuditReport) error
	grpc.ServerStream
}

type jobsStartWHOISServer struct {
	grpc.ServerStream
}

func (x *jobsStartWHOISServer) Send(m *TargetAuditReport) error {
	return x.ServerStream.SendMsg(m)
}

// Jobs_ServiceDesc is the grpc.ServiceDesc for Jobs service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Jobs_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "contracts.Jobs",
	HandlerType: (*JobsServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StartOSS",
			Handler:       _Jobs_StartOSS_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "StartDNS",
			Handler:       _Jobs_StartDNS_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "StartWHOIS",
			Handler:       _Jobs_StartWHOIS_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "agent.proto",
}

// ConfigurationClient is the client API for Configuration service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ConfigurationClient interface {
	// Reconfigure used to configure agent, returns new config
	Reconfigure(ctx context.Context, in *AgentConfig, opts ...grpc.CallOption) (*AgentConfig, error)
	RetrieveConfig(ctx context.Context, in *None, opts ...grpc.CallOption) (*AgentConfig, error)
}

type configurationClient struct {
	cc grpc.ClientConnInterface
}

func NewConfigurationClient(cc grpc.ClientConnInterface) ConfigurationClient {
	return &configurationClient{cc}
}

func (c *configurationClient) Reconfigure(ctx context.Context, in *AgentConfig, opts ...grpc.CallOption) (*AgentConfig, error) {
	out := new(AgentConfig)
	err := c.cc.Invoke(ctx, "/contracts.Configuration/Reconfigure", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *configurationClient) RetrieveConfig(ctx context.Context, in *None, opts ...grpc.CallOption) (*AgentConfig, error) {
	out := new(AgentConfig)
	err := c.cc.Invoke(ctx, "/contracts.Configuration/RetrieveConfig", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConfigurationServer is the server API for Configuration service.
// All implementations must embed UnimplementedConfigurationServer
// for forward compatibility
type ConfigurationServer interface {
	// Reconfigure used to configure agent, returns new config
	Reconfigure(context.Context, *AgentConfig) (*AgentConfig, error)
	RetrieveConfig(context.Context, *None) (*AgentConfig, error)
	mustEmbedUnimplementedConfigurationServer()
}

// UnimplementedConfigurationServer must be embedded to have forward compatible implementations.
type UnimplementedConfigurationServer struct {
}

func (UnimplementedConfigurationServer) Reconfigure(context.Context, *AgentConfig) (*AgentConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Reconfigure not implemented")
}
func (UnimplementedConfigurationServer) RetrieveConfig(context.Context, *None) (*AgentConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RetrieveConfig not implemented")
}
func (UnimplementedConfigurationServer) mustEmbedUnimplementedConfigurationServer() {}

// UnsafeConfigurationServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ConfigurationServer will
// result in compilation errors.
type UnsafeConfigurationServer interface {
	mustEmbedUnimplementedConfigurationServer()
}

func RegisterConfigurationServer(s grpc.ServiceRegistrar, srv ConfigurationServer) {
	s.RegisterService(&Configuration_ServiceDesc, srv)
}

func _Configuration_Reconfigure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AgentConfig)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigurationServer).Reconfigure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Configuration/Reconfigure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigurationServer).Reconfigure(ctx, req.(*AgentConfig))
	}
	return interceptor(ctx, in, info, handler)
}

func _Configuration_RetrieveConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(None)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigurationServer).RetrieveConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Configuration/RetrieveConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigurationServer).RetrieveConfig(ctx, req.(*None))
	}
	return interceptor(ctx, in, info, handler)
}

// Configuration_ServiceDesc is the grpc.ServiceDesc for Configuration service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Configuration_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "contracts.Configuration",
	HandlerType: (*ConfigurationServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Reconfigure",
			Handler:    _Configuration_Reconfigure_Handler,
		},
		{
			MethodName: "RetrieveConfig",
			Handler:    _Configuration_RetrieveConfig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "agent.proto",
}
