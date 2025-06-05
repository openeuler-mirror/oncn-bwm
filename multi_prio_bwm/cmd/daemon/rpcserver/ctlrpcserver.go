package rpcserver

import (
	"context"
	"fmt"
	daemon_rpc "oncn-bwm/api/v1"
	"oncn-bwm/cmd/daemon/common"
	bpf "oncn-bwm/pkg/bpfgo"
	"strconv"
	"strings"

	"oncn-bwm/pkg/nets"

	log "github.com/sirupsen/logrus"
)

func (rpcService *RpcService) SetFlow(ctx context.Context, req *daemon_rpc.QosFlow) (*daemon_rpc.SetFlowReply, error) {
	log.Debugf("call SetFlow")
	rep := &daemon_rpc.SetFlowReply{Success: false}

	processInfo := &common.ProcessInfo{
		Ip:        req.Ip,
		Port:      req.Port,
		ProcessId: strings.Join([]string{req.Direct, req.Ip, strconv.Itoa(int(req.Port))}, ":"),
	}

	log.Infof("allocate localid for flow request [%+v]", req)
	id, err := rpcService.IDmanager.AllocateProcessId(processInfo)
	if err != nil {
		err = fmt.Errorf("allcate processInfo %+v localid err: %v", processInfo, err)
		log.Errorf("%v", err)
		rep.FailReason = err.Error()
		return rep, err
	}
	processInfo.LocalId = id

	idKey := bpf.TcEdtIdKey{
		Ip:   nets.ConvertIpToUint32(req.Ip),
		Port: req.Port,
	}

	if req.Direct == "egress" {
		processInfo.NetQosReq.EgressQosConfig.BandWidthRequestM = req.SendBandWidthRequestM
		processInfo.NetQosReq.EgressQosConfig.BandWidthLimitM = req.SendBandWidthLimitM
		processInfo.NetQosReq.EgressQosConfig.Priority = req.SendPriority
		egressClassid := bpf.GenerateClassId(req.SendPriority, id)
		bpf.Edt.UpdateEgressThrottleId(idKey, egressClassid)
		if err != nil {
			err = fmt.Errorf("UpdateEgressThrottleId failed: %v", err)
			log.Errorf("%v", err)
			return rep, err
		}
		bpf.Edt.AddEgressConfig(uint32(id), processInfo.NetQosReq.EgressQosConfig)
	} else if req.Direct == "ingress" {
		processInfo.NetQosReq.IngressQosConfig.BandWidthRequestM = req.RecvBandWidthRequestM
		processInfo.NetQosReq.IngressQosConfig.BandWidthLimitM = req.RecvBandWidthLimitM
		processInfo.NetQosReq.IngressQosConfig.Priority = req.RecvPriority
		ingressClassid := bpf.GenerateClassId(req.RecvPriority, id)
		bpf.Edt.UpdateIngressThrottleId(idKey, ingressClassid)
		if err != nil {
			err = fmt.Errorf("UpdateEgressThrottleId failed: %v", err)
			log.Errorf("%v", err)
			return rep, err
		}
		bpf.Edt.AddIngressConfig(uint32(id), processInfo.NetQosReq.IngressQosConfig)
	}

	rpcService.IDmanager.InsertProcessInfo(processInfo.ProcessId, processInfo)

	rep.LocalId = uint32(id)
	rep.Success = true

	return rep, err
}

func (rpcService *RpcService) UnSetFlow(ctx context.Context, req *daemon_rpc.QosFlow) (*daemon_rpc.UnSetFlowReply, error) {
	log.Debugf("call UnSetFlow")
	processId := strings.Join([]string{req.Direct, req.Ip, strconv.Itoa(int(req.Port))}, ":")

	processInfo, err := rpcService.IDmanager.LookupProcessInfo(processId)
	if processInfo == nil || err != nil {
		err = fmt.Errorf("get %s processInfo failed, err: %v", processId, err)
		log.Errorf("%v", err)
	} else {
		log.Debugf("UnSetFlow get processInfo [%+v]", processInfo)
		idKey := bpf.TcEdtIdKey{
			Ip:   nets.ConvertIpToUint32(processInfo.Ip),
			Port: processInfo.Port,
		}
		if req.Direct == "egress" {
			bpf.Edt.SingleWriteEgressThrottleStat(uint32(processInfo.LocalId), bpf.TcEdtThrottleStat{})
			bpf.Edt.SingleWriteEgressThrottleCfg(uint32(processInfo.LocalId), bpf.TcEdtThrottleCfg{})
			bpf.Edt.DeleteEgressThrottleId(idKey)
		} else if req.Direct == "ingress" {
			bpf.Edt.SingleWriteIngressThrottleStat(uint32(processInfo.LocalId), bpf.TcEdtThrottleStat{})
			bpf.Edt.SingleWriteIngressThrottleCfg(uint32(processInfo.LocalId), bpf.TcEdtThrottleCfg{})
			bpf.Edt.DeleteIngressThrottleId(idKey)
		}
	}

	rpcService.IDmanager.ReleaseProcessInfo(processId)

	return &daemon_rpc.UnSetFlowReply{Success: true}, nil
}

func (rpcService *RpcService) ListQosFlow(ctx context.Context, _ *daemon_rpc.EmptyRequest) (*daemon_rpc.QosFlows, error) {
	var processInfoSlice []*daemon_rpc.QosFlow
	for _, processinfo := range rpcService.IDmanager.ListProcessInfo() {
		copyOfInfo := daemon_rpc.QosFlow{
			Ip:                    processinfo.Ip,
			Port:                  processinfo.Port,
			LocalId:               uint32(processinfo.LocalId),
			SendBandWidthRequestM: processinfo.EgressQosConfig.BandWidthRequestM,
			SendBandWidthLimitM:   processinfo.EgressQosConfig.BandWidthLimitM,
			SendPriority:          processinfo.EgressQosConfig.Priority,
			RecvBandWidthRequestM: processinfo.IngressQosConfig.BandWidthRequestM,
			RecvBandWidthLimitM:   processinfo.IngressQosConfig.BandWidthLimitM,
			RecvPriority:          processinfo.IngressQosConfig.Priority,
		}
		processInfoSlice = append(processInfoSlice, &copyOfInfo)
	}
	return &daemon_rpc.QosFlows{QosFlows: processInfoSlice}, nil
}

func (rpcService *RpcService) ListQosPodInfo(ctx context.Context, req *daemon_rpc.EmptyRequest) (*daemon_rpc.PodInfos, error) {
	var podInfoSlice []*daemon_rpc.PodInfo
	for _, podinfo := range rpcService.IDmanager.ListPodInfo() {
		copyOfInfo := daemon_rpc.PodInfo{
			K8SPodName:            podinfo.K8SPodName,
			K8SPodNamespace:       podinfo.K8SPodNamespace,
			ContainerId:           podinfo.ContainerId,
			LocalId:               uint32(podinfo.LocalId),
			SendBandWidthRequestM: podinfo.EgressQosConfig.BandWidthRequestM,
			SendBandWidthLimitM:   podinfo.EgressQosConfig.BandWidthLimitM,
			SendPriority:          podinfo.EgressQosConfig.Priority,
			RecvBandWidthRequestM: podinfo.IngressQosConfig.BandWidthRequestM,
			RecvBandWidthLimitM:   podinfo.IngressQosConfig.BandWidthLimitM,
			RecvPriority:          podinfo.IngressQosConfig.Priority,
		}
		podInfoSlice = append(podInfoSlice, &copyOfInfo)
	}
	return &daemon_rpc.PodInfos{PodInfos: podInfoSlice}, nil
}
