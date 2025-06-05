package rpc

import (
	"context"
	"fmt"
	"net"
	daemon_rpc "oncn-bwm/api/v1"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"
)

const (
	NetQosSocketPath  string = "/var/run/bwm/netqos.socket"
	DefaultCniTimeout        = 60 * time.Second
)

type CniRpcClient struct {
	daemon_rpc.NetQosRpcClient
}

func newRpcClient(socketPath string) (*grpc.ClientConn, func(), error) {
	timeoutCtx, cancel := context.WithTimeout(context.TODO(), DefaultCniTimeout)
	grpcConn, err := grpc.DialContext(timeoutCtx, socketPath, grpc.WithInsecure(), grpc.WithContextDialer(
		func(ctx context.Context, s string) (net.Conn, error) {
			unixAddr, err := net.ResolveUnixAddr("unix", socketPath)
			if err != nil {
				return nil, fmt.Errorf("error while resolve unix addr:%w", err)
			}
			d := net.Dialer{}
			return d.DialContext(timeoutCtx, "unix", unixAddr.String())
		}))
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("error dial to %s, %w", socketPath, err)
	}

	return grpcConn, func() {
		grpcConn.Close()
		cancel()
	}, nil
}

func NewNetQosRpcClient() (*CniRpcClient, func(), error) {
	grpcConn, closeFunc, err := newRpcClient(NetQosSocketPath)
	if err != nil {
		return nil, closeFunc, err
	}
	grpcClient := daemon_rpc.NewNetQosRpcClient(grpcConn)
	return &CniRpcClient{grpcClient}, closeFunc, nil
}

func (cniRpcClient *CniRpcClient) SetQosRequest(setQosRequest *daemon_rpc.SetQosRequest) (*daemon_rpc.SetQosReply, error) {
	timeoutContext, cancel := context.WithTimeout(context.TODO(), DefaultCniTimeout)
	defer cancel()
	setQosReply, err := cniRpcClient.SetQos(
		timeoutContext,
		setQosRequest,
	)

	if err != nil {
		return nil, fmt.Errorf("error grpcClient.SetQos ,pod %s/%s, %w", setQosRequest.K8SPodNamespace, setQosRequest.K8SPodName, err)
	}
	return setQosReply, nil
}

func (cniRpcClient *CniRpcClient) UnSetQosRequest(unSetQosRequest *daemon_rpc.UnSetQosRequest) (*daemon_rpc.UnSetQosReply, error) {
	timeoutContext, cancel := context.WithTimeout(context.TODO(), DefaultCniTimeout)
	defer cancel()
	UnSetQosReply, err := cniRpcClient.UnSetQos(
		timeoutContext,
		unSetQosRequest,
	)

	if err != nil {
		return nil, fmt.Errorf("error grpcClient.SetQos ,pod %s/%s, %w", unSetQosRequest.K8SPodNamespace, unSetQosRequest.K8SPodName, err)
	}
	return UnSetQosReply, nil
}

func (cniRpcClient *CniRpcClient) SetFlowRequest(setQosFlow *daemon_rpc.QosFlow) (*daemon_rpc.SetFlowReply, error) {
	timeoutContext, cancel := context.WithTimeout(context.TODO(), DefaultCniTimeout)
	defer cancel()

	setFlowReply, err := cniRpcClient.SetFlow(
		timeoutContext,
		setQosFlow,
	)

	if err != nil {
		return nil, fmt.Errorf("grpcClient.SetQosFlow failed, err:%v", err)
	}
	return setFlowReply, nil
}

func (cniRpcClient *CniRpcClient) UnSetFlowRequest(unSetQosFlow *daemon_rpc.QosFlow) (*daemon_rpc.UnSetFlowReply, error) {
	timeoutContext, cancel := context.WithTimeout(context.TODO(), DefaultCniTimeout)
	defer cancel()
	unSetFlowReply, err := cniRpcClient.UnSetFlow(
		timeoutContext,
		unSetQosFlow,
	)

	if err != nil {
		return nil, fmt.Errorf("grpcClient.UnSetQosFlow failed, err: %v", err)
	}
	return unSetFlowReply, nil
}

func RunRpcServer(rpcSrv daemon_rpc.NetQosRpcServer, chErrorCome chan error) {
	if err := os.MkdirAll(filepath.Dir(NetQosSocketPath), 0700); err != nil {
		chErrorCome <- fmt.Errorf("mkdirAll %v fail! err: %v", NetQosSocketPath, err)
		return
	}

	if err := syscall.Unlink(NetQosSocketPath); err != nil && !os.IsNotExist(err) {
		chErrorCome <- fmt.Errorf("unlink %v fail! err: %v", NetQosSocketPath, err)
		return
	}

	mask := syscall.Umask(0777)
	defer syscall.Umask(mask)

	l, err := net.Listen("unix", NetQosSocketPath)
	if err != nil {
		chErrorCome <- fmt.Errorf("listen %v fail! err: %v", NetQosSocketPath, err)
		return
	}

	grpcServer := grpc.NewServer()
	daemon_rpc.RegisterNetQosRpcServer(grpcServer, rpcSrv)
	err = grpcServer.Serve(l)
	if err != nil {
		grpcServer.Stop()
		chErrorCome <- fmt.Errorf("grpcServer.Serve fail! err: %v", err)
		return
	}
}
