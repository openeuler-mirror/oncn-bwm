package k8slib

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	daemon_rpc "oncn-bwm/api/v1"
	"oncn-bwm/cmd/daemon/common"
	"oncn-bwm/pkg/nets"
	"oncn-bwm/pkg/rpc"
	"os"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	QosegressAnno      string = "oncn-bwm.openeuler.org/egress-bandwidth"
	QosingressAnno     string = "oncn-bwm.openeuler.org/ingress-bandwidth"
	QosLocalIdAnno     string = "oncn-bwm.openeuler.org/localid"
	QosContainerIdAnno string = "oncn-bwm.openeuler.org/containerid"
	QosVethIpv4Anno    string = "oncn-bwm.openeuler.org/ipv4"
	QosVethIpv6Anno    string = "oncn-bwm.openeuler.org/ipv6"
)

var bandwidthAnoSuffix = []string{"M", "m", "Mb"}

// GetBandwidthAnoSuffix 返回 BandwidthAnoSuffix 的副本，以防止修改。
func GetBandwidthAnoSuffix() []string {
	return append([]string(nil), bandwidthAnoSuffix...)
}

type NetQosAnnotation struct {
	Limit    string `json:"limit"`    //最大带宽限制
	Request  string `json:"request"`  //最小带宽保障
	Priority string `json:"priority"` //优先级
}

type K8sClient struct {
	kubernetes.Clientset
}

type K8sCache struct {
	cache.SharedInformer
}

func trimUnit(s string, suffixes []string) string {
	s = strings.TrimSpace(s)
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return strings.TrimSuffix(s, suffix)
		}
	}
	return s
}

func parseNetQosAnnotation(annotation string, suffixes []string) (NetQosAnnotation, error) {
	var netQosAnnotation NetQosAnnotation
	if err := json.Unmarshal([]byte(annotation), &netQosAnnotation); err != nil {
		return netQosAnnotation, fmt.Errorf("parsing annotation %s err: %v", annotation, err)
	}
	return netQosAnnotation, nil
}

func parseUintOrDefault(s string, base int, bitSize int, suffixes []string) (uint64, error) {
	if s != "" {
		s = trimUnit(s, suffixes)
		return strconv.ParseUint(s, base, bitSize)
	}
	return 0, nil
}

func NewK8sClient() (*K8sClient, *K8sCache, chan struct{}, error) {
	stopCh := make(chan struct{})
	var config *rest.Config
	var err error

	// 在集群内部运行时使用 in-cluster 配置
	config, err = rest.InClusterConfig()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cluster config err: %v", err)
	}

	// 创建客户端
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new k8scilent err: %v", err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		err := fmt.Errorf("NODE_NAME environment variable must be set")
		return nil, nil, nil, err
	}

	watchlist := cache.NewListWatchFromClient(
		clientSet.CoreV1().RESTClient(),
		string(corev1.ResourcePods),
		metav1.NamespaceAll,
		fields.OneTermEqualSelector("spec.nodeName", nodeName),
	)

	informer := cache.NewSharedInformer(
		watchlist,
		&corev1.Pod{},
		time.Minute*10,
	)

	// 开始监听和同步
	go informer.Run(stopCh)
	if !cache.WaitForCacheSync(stopCh, informer.HasSynced) {
		err := fmt.Errorf("wait for cache sync err: %v", err)
		return nil, nil, nil, err
	}

	return &K8sClient{*clientSet}, &K8sCache{informer}, stopCh, nil
}

func NewController() error {
	stopCh := make(chan struct{})
	var config *rest.Config
	var err error

	// 在集群内部运行时使用 in-cluster 配置
	config, err = rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("cluster config err: %v", err)
	}

	// 创建客户端
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("new k8scilent err: %v", err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		err := fmt.Errorf("NODE_NAME environment variable must be set")
		return err
	}

	watchlist := cache.NewListWatchFromClient(
		clientSet.CoreV1().RESTClient(),
		string(corev1.ResourcePods),
		metav1.NamespaceAll,
		fields.OneTermEqualSelector("spec.nodeName", nodeName),
	)

	informer := cache.NewSharedInformer(
		watchlist,
		&corev1.Pod{},
		time.Minute*10,
	)

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			if pod.Spec.HostNetwork {
				handleHostNetworkPod(pod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			if pod.Spec.HostNetwork {
				handleHostNetworkPodDeletion(pod)
			}
		},
	})

	// 开始监听和同步
	go informer.Run(stopCh)
	if !cache.WaitForCacheSync(stopCh, informer.HasSynced) {
		err := fmt.Errorf("wait for cache sync err: %v", err)
		return err
	}

	return nil
}

func handleHostNetworkPod(pod *corev1.Pod) {
	rpcClient, closeConn, err := rpc.NewNetQosRpcClient()
	if err != nil {
		fmt.Printf("new rpc client err: %v\n", err)
		return
	}
	defer closeConn()

	var hostport uint32
	qosSet, err := GetPodNetQosRequest(pod)
	if err != nil {
		fmt.Printf("Error getting QoS request for pod %s/%s: %v\n", pod.Namespace, pod.Name, err)
		return
	}

	var directions []string

	_, egressAnnoExists := pod.Annotations[QosegressAnno]
	_, ingressAnnoExists := pod.Annotations[QosingressAnno]

	if egressAnnoExists {
		directions = append(directions, "egress")
	}
	if ingressAnnoExists {
		directions = append(directions, "ingress")
	}

	if len(directions) == 0 {
		return
	}

	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.HostPort > 0 {
				hostport = uint32(port.HostPort)
				break
			}
		}
	}

	fmt.Printf("hostport is : %d\n", hostport)
	for _, direction := range directions {
		req := &daemon_rpc.QosFlow{
			Direct: direction,
			Ip:     pod.Status.PodIP,
			Port:   nets.ConvertPortToBigEndian(hostport),
		}

		if direction == "egress" {
			req.SendPriority = qosSet.EgressQosConfig.Priority
			req.SendBandWidthRequestM = qosSet.EgressQosConfig.BandWidthRequestM
			req.SendBandWidthLimitM = qosSet.EgressQosConfig.BandWidthLimitM
		}
		if direction == "ingress" {
			req.RecvPriority = qosSet.IngressQosConfig.Priority
			req.RecvBandWidthRequestM = qosSet.IngressQosConfig.BandWidthRequestM
			req.RecvBandWidthLimitM = qosSet.IngressQosConfig.BandWidthLimitM
		}

		rep, err := rpcClient.SetFlowRequest(req)
		if err != nil {
			fmt.Printf("rpc setflow err: %v\n", err)
			return
		}

		if !rep.GetSuccess() {
			fmt.Printf("rpc setflow fail, reason: %s\n", rep.FailReason)
			return
		}
		fmt.Printf("set flow %s %s %d success\n", direction, req.Ip, req.Port)
	}
}

func getHostIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if ok && !ipnet.IP.IsLoopback() {
					return ipnet.IP.String(), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no suitable IP address found")
}

func handleHostNetworkPodDeletion(pod *corev1.Pod) {
	rpcClient, closeConn, err := rpc.NewNetQosRpcClient()
	if err != nil {
		fmt.Printf("new rpc client err: %v\n", err)
		return
	}
	defer closeConn()

	var hostport uint32
	if err != nil {
		fmt.Printf("Error getting QoS request for pod %s/%s: %v\n", pod.Namespace, pod.Name, err)
		return
	}

	var directions []string

	_, egressAnnoExists := pod.Annotations[QosegressAnno]
	_, ingressAnnoExists := pod.Annotations[QosingressAnno]

	if egressAnnoExists {
		directions = append(directions, "egress")
	}
	if ingressAnnoExists {
		directions = append(directions, "ingress")
	}

	if len(directions) == 0 {
		return
	}

	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.HostPort > 0 {
				hostport = uint32(port.HostPort)
				break
			}
		}
	}

	for _, direction := range directions {
		req := &daemon_rpc.QosFlow{
			Direct: direction,
			Ip:     pod.Status.PodIP,
			Port:   nets.ConvertPortToBigEndian(hostport),
		}

		rep, err := rpcClient.UnSetFlowRequest(req)
		if err != nil {
			fmt.Printf("rpc setflow err: %v\n", err)
			return
		}

		if !rep.GetSuccess() {
			fmt.Printf("rpc setflow fail, reason: %s\n", rep.FailReason)
			return
		}
		fmt.Printf("unset flow %s %s %d success\n", direction, req.Ip, req.Port)
	}
}

func (c *K8sClient) ListRunPodFromEtcd() (*corev1.PodList, error) {
	// 节点名称
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		err := fmt.Errorf("NODE_NAME environment variable must be set")
		return nil, err
	}
	return c.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName + ",status.phase=Running",
	})
}

func (c *K8sCache) ListRunPodFromCache() (*corev1.PodList, error) {
	var runningPods []*corev1.Pod
	pods := c.GetStore().List()
	// 处理运行中的 Pods
	for _, obj := range pods {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return nil, fmt.Errorf("error asserting Pod from cache: %v", obj)
		}
		if pod.Status.Phase == corev1.PodRunning {
			runningPods = append(runningPods, pod)
		}
	}

	// 将收集到的运行中的 Pods 转换为 PodList
	podList := &corev1.PodList{
		Items: make([]corev1.Pod, len(runningPods)),
	}
	for i, pod := range runningPods {
		podList.Items[i] = *pod
	}

	return podList, nil
}

func GetPodNetQosRequest(pod *corev1.Pod) (*common.NetQosReq, error) {
	qosSet := &common.NetQosReq{}

	for _, annoKey := range []struct {
		key     string
		setFunc func(uint32, uint64, uint64)
	}{
		{QosegressAnno, func(priority uint32, limit, request uint64) {
			qosSet.EgressQosConfig.Priority = priority
			qosSet.EgressQosConfig.BandWidthLimitM = limit
			qosSet.EgressQosConfig.BandWidthRequestM = request
		}},
		{QosingressAnno, func(priority uint32, limit, request uint64) {
			qosSet.IngressQosConfig.Priority = priority
			qosSet.IngressQosConfig.BandWidthLimitM = limit
			qosSet.IngressQosConfig.BandWidthRequestM = request
		}},
	} {
		if annoValue, ok := pod.Annotations[annoKey.key]; ok {
			netQosAnnotation, err := parseNetQosAnnotation(annoValue, GetBandwidthAnoSuffix())
			if err != nil {
				return qosSet, fmt.Errorf("parse pod %s/%s annotation err: %v", pod.Namespace, pod.Name, err)
			}

			priority, err := parseUintOrDefault(netQosAnnotation.Priority, 10, 32, GetBandwidthAnoSuffix())
			if err != nil {
				return qosSet, fmt.Errorf("parsing %s Priority %s err %v", annoKey.key, netQosAnnotation.Priority, err)
			}

			if priority > 2 {
				fmt.Printf("the %s priority value is set to %d, exceed the maximum value of 2, actual priority value will be set to 2\n", annoKey.key, priority)
				priority = 2
			}

			limit, err := parseUintOrDefault(netQosAnnotation.Limit, 10, 64, GetBandwidthAnoSuffix())
			if err != nil {
				return qosSet, fmt.Errorf("parsing %s limit %s err %v", annoKey.key, netQosAnnotation.Limit, err)
			}

			request, err := parseUintOrDefault(netQosAnnotation.Request, 10, 64, GetBandwidthAnoSuffix())
			if err != nil {
				return qosSet, fmt.Errorf("parsing %s request %s err %v", annoKey.key, netQosAnnotation.Request, err)
			}

			annoKey.setFunc(uint32(priority), limit, request)
		}
	}
	return qosSet, nil
}

func (c *K8sClient) GetPodFromEtcd(namespace string, name string) (*corev1.Pod, error) {
	pod, err := c.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return pod, nil
}

func (c *K8sClient) PatchPodQosInfo(pod *corev1.Pod, patchData *common.PatchPodData) error {
	patchStr := fmt.Sprintf(`{
		"metadata": {
			"annotations": {
				"%s": "%s",
				"%s": "%s",
				"%s": "%s",
				"%s": "%s"
			}
		}
		}`, QosLocalIdAnno, fmt.Sprintf("%d", patchData.LocalId), QosContainerIdAnno, patchData.ContainerId, QosVethIpv4Anno, patchData.VethIpv4, QosVethIpv6Anno, patchData.VethIpv6)
	patchByte := []byte(patchStr)
	_, err := c.CoreV1().Pods(pod.Namespace).Patch(context.Background(), pod.Name, types.MergePatchType, patchByte, metav1.PatchOptions{})

	return err
}

func GetPodPatchData(pod *corev1.Pod) (*common.PatchPodData, error) {
	patchData := &common.PatchPodData{}
	// 检索 localid 注解值
	if localIDValue, ok := pod.Annotations[QosLocalIdAnno]; ok {
		if containerIDValue, ok := pod.Annotations[QosContainerIdAnno]; ok {
			localID, err := strconv.Atoi(localIDValue)
			if err != nil {
				return nil, fmt.Errorf("%s converting localid to int, err %v", localIDValue, err)
			}
			patchData.LocalId = uint16(localID)
			patchData.ContainerId = containerIDValue
		}
	}
	if vethIpv4Value, ok := pod.Annotations[QosVethIpv4Anno]; ok {
		patchData.VethIpv4 = vethIpv4Value
	}
	if vethIpv6Value, ok := pod.Annotations[QosVethIpv6Anno]; ok {
		patchData.VethIpv6 = vethIpv6Value
	}
	return patchData, nil
}
