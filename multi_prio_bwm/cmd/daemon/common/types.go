package common

type QosConfig struct {
	BandWidthRequestM uint64
	BandWidthLimitM   uint64
	Priority          uint32
}

type NetQosReq struct {
	EgressQosConfig  QosConfig
	IngressQosConfig QosConfig
}

type VethInfo struct {
	HostMac      string
	VethHostIdx  int32
	VethLXCMac   string
	VethHostName string
	VethLXCName  string
	VethIpv4     string
	VethIpv6     string
}

type PodInfo struct {
	NetQosReq
	LocalId         uint16
	K8SPodName      string
	K8SPodNamespace string
	ContainerId     string
	Netns           string
	VethHostName    string
	VethLXCName     string
	VethIpv4        string
	VethIpv6        string
}

type PatchPodData struct {
	LocalId     uint16
	ContainerId string
	VethIpv4    string
	VethIpv6    string
}

type ProcessInfo struct {
	NetQosReq
	ProcessId string
	LocalId   uint16
	Ip        string
	Port      uint32
}
