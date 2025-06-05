package main

import (
	"fmt"
	"oncn-bwm/cmd/daemon/common"
	"oncn-bwm/cmd/daemon/idmanager"
	"oncn-bwm/cmd/daemon/k8slib"
	"oncn-bwm/cmd/daemon/rpcserver"
	bpf "oncn-bwm/pkg/bpfgo"
	"oncn-bwm/pkg/nets"
	"oncn-bwm/pkg/rpc"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	IfbName = "bwmifb0"
	EdtBpf  *bpf.Tcbpf
)

func PreRun() error {
	checkMap := func(mapPath string) error {
		if _, err := os.Stat(mapPath); err != nil {
			if os.IsNotExist(err) {
				log.Warningf("%s Map is not pinned.", mapPath)
			} else {
				log.Warningf("Failed to check if %s is pinned: %v\n", mapPath, err)
			}
			return err
		}
		return nil
	}
	bpfMapArr := []string{
		bpf.EgressThrottleCfgMapPath,
		bpf.EgressThrottleStatMapPath,
		bpf.IngressThrottleCfgMapPath,
		bpf.IngressThrottleStatMapPath,
		bpf.EgressThrottleIdMapPath,
		bpf.IngressThrottleIdMapPath,
	}
	i := 0
	//wait until alg-daemon pin the map
	for i < len(bpfMapArr) {
		if nil == checkMap(bpfMapArr[i]) {
			log.Debugf("%s has been pinned", bpfMapArr[i])
			i++ // 当元素合格时，移动到下一个元素
		} else {
			log.Debugf("waiting for %s pinned", bpfMapArr[i])
			time.Sleep(3 * time.Second)
		}
	}

	return nil
}

func recoverIdmanagerFromCache(podCache *k8slib.K8sCache, idManager *idmanager.IDManager) error {
	podList, err := podCache.ListRunPodFromCache()
	if err != nil {
		return fmt.Errorf("list localpod err: %v", err)
	}
	for _, pod := range podList.Items {
		patchData, err := k8slib.GetPodPatchData(&pod)
		if err != nil {
			return fmt.Errorf("failed to get patch data for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}

		if patchData.ContainerId == "" {
			continue
		}

		qosSet, err := k8slib.GetPodNetQosRequest(&pod)
		if err != nil {
			log.Errorf("failed to get QoS request for pod %s/%s: %v", pod.Namespace, pod.Name, err)
			continue
		}

		podInfo := &common.PodInfo{
			LocalId:         patchData.LocalId,
			K8SPodName:      pod.Name,
			K8SPodNamespace: pod.Namespace,
			ContainerId:     patchData.ContainerId,
			NetQosReq:       *qosSet,
			VethIpv4:        patchData.VethIpv4,
			VethIpv6:        patchData.VethIpv6,
		}
		log.Infof("recover idmanager podinfo %+v", podInfo)
		idManager.InsertPodInfo(patchData.ContainerId, podInfo)
	}
	return nil
}

func Run() error {
	var err error
	//k8s client
	k8sClient, podcache, stopCacheSyncChan, err := k8slib.NewK8sClient()
	if err != nil {
		return fmt.Errorf("new k8sclient and pod cacahe err: %v", err)
	}
	//恢复idmanager数据
	idManager := idmanager.NewPodIDManager()
	err = recoverIdmanagerFromCache(podcache, idManager)
	if err != nil {
		return fmt.Errorf("recover idmanager err: %v", err)
	}
	//运行rpc服务
	rpcErrorCh := make(chan error)
	rpcService := &rpcserver.RpcService{
		K8sClient: k8sClient,
		IDmanager: idManager,
	}
	go rpc.RunRpcServer(rpcService, rpcErrorCh)
	log.Debugf("rpcserver start")
	defer func() {
		close(rpcErrorCh)
		close(stopCacheSyncChan)
	}()

	edtBpf, err := bpf.NewTcbpf()
	if err != nil {
		log.Errorf("init edtBpf failed: %v", err)
		return err
	}

	defer func() {
		edtBpf.Close()
	}()

	err = k8slib.NewController()
	if err != nil {
		log.Errorf("NewController failed: %v", err)
		return err
	}

	//恢复已有pod的qos配置到cfg map和id map
	for _, podInfo := range idManager.ListPodInfo() {
		log.Infof("recover pod %v", podInfo)
		podEgressConfig := common.QosConfig{
			BandWidthRequestM: podInfo.NetQosReq.EgressQosConfig.BandWidthRequestM,
			BandWidthLimitM:   podInfo.NetQosReq.EgressQosConfig.BandWidthLimitM,
			Priority:          podInfo.NetQosReq.EgressQosConfig.Priority,
		}

		podIngressConfig := common.QosConfig{
			BandWidthRequestM: podInfo.NetQosReq.IngressQosConfig.BandWidthRequestM,
			BandWidthLimitM:   podInfo.NetQosReq.IngressQosConfig.BandWidthLimitM,
			Priority:          podInfo.NetQosReq.IngressQosConfig.Priority,
		}

		edtBpf.AddIngressConfig(uint32(podInfo.LocalId), podIngressConfig)
		edtBpf.AddEgressConfig(uint32(podInfo.LocalId), podEgressConfig)

		idKey := bpf.TcEdtIdKey{
			Ip:   nets.ConvertIpToUint32(podInfo.VethIpv4),
			Port: 0,
		}

		egressId := bpf.GenerateClassId(podInfo.EgressQosConfig.Priority, podInfo.LocalId)
		log.Infof("generate egressid: %d", egressId)
		if err = edtBpf.UpdateEgressThrottleId(idKey, egressId); err != nil {
			err = fmt.Errorf("UpdateEgressThrottleId failed, err: %v", err)
			log.Errorf("%v", err)
		}

		ingressId := bpf.GenerateClassId(podInfo.IngressQosConfig.Priority, podInfo.LocalId)
		log.Infof("generate ingressid: %d", ingressId)
		if err = edtBpf.UpdateIngressThrottleId(idKey, ingressId); err != nil {
			err = fmt.Errorf("UpdateIngressThrottleId failed, err: %v", err)
			log.Errorf("%v", err)
		}
	}

	setupCloseHandler()

	return err
}

func setupCloseHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGABRT, syscall.SIGTSTP)

	<-ch

	log.Warn("Signal notify exit")
}

func main() {
	log.SetLevel(log.InfoLevel)
	cmd := &cobra.Command{
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := PreRun(); err != nil {
				log.Errorf("prerune err: %v", err)
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := Run(); err != nil {
				log.Errorf("rune err: %v", err)
				return err
			}
			return nil
		},
	}

	if err := cmd.Execute(); err != nil {
		log.Errorf("bwm-daemon run failed, err: %v", err)
	}
}
