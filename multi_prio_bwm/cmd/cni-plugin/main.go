package main

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	daemon_rpc "oncn-bwm/api/v1"
	"oncn-bwm/cmd/cni-plugin/lib"
	"oncn-bwm/cmd/cni-plugin/lib/logger"
	"oncn-bwm/pkg/rpc"
	"runtime"
	"time"
)

const (
	subsys = "cni-plugin"
)

var (
	loggerCase = logger.InitializeDefaultLogger(true)
	Gitversion string
)

func cmdAdd(args *skel.CmdArgs) error {
	startTimeStamp := time.Now()

	n, _, argSpec, err := lib.ParseArgs(args)
	if err != nil {
		return fmt.Errorf("parse cni arg %v err: %v", args, err)
	}

	logger.SetLogLevel(loggerCase, n.Log_level)
	log := logger.NewLoggerField(loggerCase, subsys)

	log.Debugf("cni add start args: %+v", args)
	defer func() {
		durationTimeMs := time.Since(startTimeStamp).Milliseconds()
		log.Debugf("cni add end Consume %d ms on add cmd", durationTimeMs)
	}()

	vethPeer, err := lib.GetVethPeerInfo(args.Netns)
	if err != nil {
		return fmt.Errorf("get vethpeer info err: %v", err)
	}

	cniRpcClient, closeConn, err := rpc.NewNetQosRpcClient()
	if err != nil {
		return fmt.Errorf("new cni rpc client err: %v", err)
	}
	defer closeConn()

	setQosReq := &daemon_rpc.SetQosRequest{
		K8SPodName:      string(argSpec.K8S_POD_NAME),
		K8SPodNamespace: string(argSpec.K8S_POD_NAMESPACE),
		VethIpv4:        vethPeer.VethIP,
		VethIpv6:        vethPeer.VethIPv6,
		HostMac:         vethPeer.VethHostMac,
		VethHostIdx:     int32(vethPeer.VethHostIdx),
		VethLXCMac:      vethPeer.VethLXCMac,
		VethHostName:    vethPeer.VethHostName,
		VethLXCName:     vethPeer.VethLXCName,
		ContainerId:     args.ContainerID,
		Netns:           args.Netns,
	}
	log.Debugf("rpc request to daemonproc, req %+v", setQosReq)

	rep, err := cniRpcClient.SetQosRequest(setQosReq)
	if err != nil {
		return fmt.Errorf("cni request to daemonproc err: %v", err)
	}
	log.Debugf("daemonproc response: %+v", rep)
	if false == rep.GetSuccess() {
		return fmt.Errorf("set netqos for pod %s/%s fail, reason:%s", argSpec.K8S_POD_NAMESPACE, argSpec.K8S_POD_NAME, rep.GetFailReason())
	}

	return types.PrintResult(n.PrevResult, n.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	startTimeStamp := time.Now()

	n, _, argSpec, err := lib.ParseArgs(args)
	if err != nil {
		return fmt.Errorf("parse cni arg %v err: %v", args, err)
	}

	logger.SetLogLevel(loggerCase, n.Log_level)
	log := logger.NewLoggerField(loggerCase, subsys)

	log.Debugf("cni del start args: %+v", args)
	defer func() {
		durationTimeMs := time.Since(startTimeStamp).Milliseconds()
		log.Debugf("cni del end Consume %d ms on add cmd", durationTimeMs)
	}()

	// 出现非致命错误只打印，继续往下执行, 残留垃圾数据靠daemonproc中的gc线程回收
	vethPeer, err := lib.GetVethPeerInfo(args.Netns)
	if err != nil {
		vethPeer = &lib.VethPeer{}
		log.Warningf("get vethpeer info err: %v", err)
	}

	cniRpcClient, closeConn, err := rpc.NewNetQosRpcClient()
	if err != nil {
		return fmt.Errorf("new cni rpc client err: %v", err)
	}
	defer closeConn()

	unSetQosReq := &daemon_rpc.UnSetQosRequest{
		K8SPodName:      string(argSpec.K8S_POD_NAME),
		K8SPodNamespace: string(argSpec.K8S_POD_NAMESPACE),
		VethIpv4:        vethPeer.VethIP,
		VethIpv6:        vethPeer.VethIPv6,
		HostMac:         vethPeer.VethHostMac,
		VethHostIdx:     int32(vethPeer.VethHostIdx),
		VethLXCMac:      vethPeer.VethLXCMac,
		VethHostName:    vethPeer.VethHostName,
		VethLXCName:     vethPeer.VethLXCName,
		ContainerId:     args.ContainerID,
		Netns:           args.Netns,
	}
	log.Debugf("rpc request to daemonproc, req %+v", unSetQosReq)
	rep, err := cniRpcClient.UnSetQosRequest(unSetQosReq)
	if err != nil {
		return fmt.Errorf("cni request to daemonproc err: %v", err)
	}
	log.Debugf("daemonproc response: %+v", rep)
	if false == rep.GetSuccess() {
		log.Errorf("set netqos for pod %s/%s fail, reason:%s", argSpec.K8S_POD_NAMESPACE, argSpec.K8S_POD_NAME, rep.GetFailReason())
	}

	return nil
}

func main() {
	Version := fmt.Sprintf("%s go version %s %s/%s", Gitversion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	skel.PluginMain(cmdAdd, nil, cmdDel,
		version.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0"),
		"Bwm CNI"+Version)
}
