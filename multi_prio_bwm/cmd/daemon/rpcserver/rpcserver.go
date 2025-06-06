package rpcserver

import (
	"context"
	"fmt"
	daemon_rpc "oncn-bwm/api/v1"
	"oncn-bwm/cmd/daemon/common"
	"oncn-bwm/cmd/daemon/idmanager"
	"oncn-bwm/cmd/daemon/k8slib"
	bpf "oncn-bwm/pkg/bpfgo"
	"oncn-bwm/pkg/nets"

	log "github.com/sirupsen/logrus"
)

type RpcService struct {
	K8sClient *k8slib.K8sClient
	IDmanager *idmanager.IDManager
	daemon_rpc.UnimplementedNetQosRpcServer
}

func (rpcService *RpcService) SetQos(context context.Context, req *daemon_rpc.SetQosRequest) (*daemon_rpc.SetQosReply, error) {
	log.Debugf("call SetQos")
	rep := &daemon_rpc.SetQosReply{Success: false}
	pod, err := rpcService.K8sClient.GetPodFromEtcd(req.GetK8SPodNamespace(), req.GetK8SPodName())
	if err != nil {
		err = fmt.Errorf("get pod %s/%s err: %v", req.GetK8SPodNamespace(), req.GetK8SPodName(), err)
		log.Errorf("%v", err)
		rep.FailReason = err.Error()
		return rep, err
	}
	qosSet, err := k8slib.GetPodNetQosRequest(pod)
	if err != nil {
		err = fmt.Errorf("get pod %s/%s netqos err: %v", pod.Namespace, pod.Name, err)
		log.Errorf("%v", err)
		rep.FailReason = err.Error()
		return rep, err
	}
	podInfo := &common.PodInfo{
		NetQosReq:       *qosSet,
		K8SPodName:      pod.Name,
		K8SPodNamespace: pod.Namespace,
		ContainerId:     req.GetContainerId(),
		Netns:           req.GetNetns(),
		VethHostName:    req.GetVethHostName(),
		VethLXCName:     req.GetVethLXCName(),
		VethIpv4:        req.GetVethIpv4(),
		VethIpv6:        req.GetVethIpv6(),
	}
	log.Infof("allocate localid for podInfo %+v", podInfo)
	id, err := rpcService.IDmanager.AllocatePodId(podInfo)
	if err != nil {
		err = fmt.Errorf("allcate podInfo %+v localid err: %v", podInfo, err)
		log.Errorf("%v", err)
		rep.FailReason = err.Error()
		return rep, err
	}
	podInfo.LocalId = id

	patchData := &common.PatchPodData{
		LocalId:     id,
		ContainerId: req.GetContainerId(),
		VethIpv4:    req.GetVethIpv4(),
		VethIpv6:    req.GetVethIpv6(),
	}
	log.Infof("patch pod %s/%s %+v", pod.Namespace, pod.Name, patchData)
	err = rpcService.K8sClient.PatchPodQosInfo(pod, patchData)
	if err != nil {
		err = fmt.Errorf("patch pod %s/%s %+v err %v", pod.Namespace, pod.Name, patchData, err)
		log.Errorf("%v", err)
		rep.FailReason = err.Error()
		return rep, err
	}

	idKey := bpf.TcEdtIdKey{
		Ip:   nets.ConvertIpToUint32(req.GetVethIpv4()),
		Port: 0,
	}

	log.Infof("idKey: %v", idKey)
	egressId := bpf.GenerateClassId(podInfo.EgressQosConfig.Priority, podInfo.LocalId)
	log.Infof("generate egressid: %d", egressId)
	if err = bpf.Edt.UpdateEgressThrottleId(idKey, egressId); err != nil {
		err = fmt.Errorf("UpdateEgressThrottleId failed, err: %v", err)
		log.Errorf("%v", err)
		return rep, err
	}

	ingressId := bpf.GenerateClassId(podInfo.IngressQosConfig.Priority, podInfo.LocalId)
	log.Infof("generate ingressid: %d", ingressId)
	if err = bpf.Edt.UpdateIngressThrottleId(idKey, ingressId); err != nil {
		err = fmt.Errorf("UpdateIngressThrottleId failed, err: %v", err)
		log.Errorf("%v", err)
		return rep, err
	}

	bpf.Edt.AddEgressConfig(uint32(id), qosSet.EgressQosConfig)
	bpf.Edt.AddIngressConfig(uint32(id), qosSet.IngressQosConfig)
	rpcService.IDmanager.InsertPodInfo(patchData.ContainerId, podInfo)

	rep.LocalId = uint32(id)
	rep.Success = true

	return rep, err
}

func (rpcService *RpcService) UnSetQos(context context.Context, req *daemon_rpc.UnSetQosRequest) (*daemon_rpc.UnSetQosReply, error) {
	log.Debugf("call UnSetQos")
	podInfo, err := rpcService.IDmanager.LookupPodInfoByContainId(req.ContainerId)
	if podInfo == nil || err != nil {
		err = fmt.Errorf("get podInfo %s/%s failed, err: %v", req.GetK8SPodNamespace(), req.GetK8SPodName(), err)
		log.Errorf("%v", err)
	} else {

		log.Debugf("UnSetQos get podInfo %+v", podInfo)
		bpf.Edt.SingleWriteEgressThrottleStat(uint32(podInfo.LocalId), bpf.TcEdtThrottleStat{})
		bpf.Edt.SingleWriteEgressThrottleCfg(uint32(podInfo.LocalId), bpf.TcEdtThrottleCfg{})

		bpf.Edt.SingleWriteIngressThrottleStat(uint32(podInfo.LocalId), bpf.TcEdtThrottleStat{})
		bpf.Edt.SingleWriteIngressThrottleCfg(uint32(podInfo.LocalId), bpf.TcEdtThrottleCfg{})

		idKey := bpf.TcEdtIdKey{
			Ip:   nets.ConvertIpToUint32(podInfo.VethIpv4),
			Port: 0,
		}
		bpf.Edt.DeleteEgressThrottleId(idKey)
		bpf.Edt.DeleteIngressThrottleId(idKey)
	}

	rpcService.IDmanager.ReleasePodIdByContainerId(req.ContainerId)

	return &daemon_rpc.UnSetQosReply{Success: true}, nil
}
