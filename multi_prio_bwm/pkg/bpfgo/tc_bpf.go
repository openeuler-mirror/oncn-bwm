package bpf

import (
	"fmt"
	"oncn-bwm/cmd/daemon/common"
	"time"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
)

const (
	PerMB          = (1024 * 1024 / 8) // 1MB
	PeriodInterval = 10                // 10ms
)

const (
	EgressBpfSection           = "tc_egress"
	IngressBpfSection          = "tc_ingress"
	EdtBpfProgPath             = "/usr/share/bwm/tcedt_bpfel.o"
	EgressThrottleCfgMapPath   = "/sys/fs/bpf/tc/globals/egress_cfg"
	EgressThrottleStatMapPath  = "/sys/fs/bpf/tc/globals/egress_stat"
	IngressThrottleCfgMapPath  = "/sys/fs/bpf/tc/globals/ingress_cfg"
	IngressThrottleStatMapPath = "/sys/fs/bpf/tc/globals/ingress_stat"
	EgressThrottleIdMapPath    = "/sys/fs/bpf/tc/globals/egress_id"
	IngressThrottleIdMapPath   = "/sys/fs/bpf/tc/globals/ingress_id"
)

type Tcbpf struct {
	BpfFileName            string
	BpfProgPath            string
	EgressThrottleCfgMap   *ebpf.Map
	EgressThrottleStatMap  *ebpf.Map
	IngressThrottleCfgMap  *ebpf.Map
	IngressThrottleStatMap *ebpf.Map
	EgressThrottleIdMap    *ebpf.Map
	IngressThrottleIdMap   *ebpf.Map
}

var Edt *Tcbpf

func NewTcbpf() (*Tcbpf, error) {
	egressThrottleCfg, err := ebpf.LoadPinnedMap(EgressThrottleCfgMapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return &Tcbpf{}, fmt.Errorf("failed to get bpf map: %s, err: %v", EgressThrottleCfgMapPath, err)
	}

	egressThrottleStat, err := ebpf.LoadPinnedMap(EgressThrottleStatMapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return &Tcbpf{}, fmt.Errorf("failed to get bpf map: %s, err: %v", EgressThrottleStatMapPath, err)
	}

	ingressThrottleCfg, err := ebpf.LoadPinnedMap(IngressThrottleCfgMapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return &Tcbpf{}, fmt.Errorf("failed to get bpf map: %s, err: %v", IngressThrottleCfgMapPath, err)
	}

	ingressThrottleStat, err := ebpf.LoadPinnedMap(IngressThrottleStatMapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return &Tcbpf{}, fmt.Errorf("failed to get bpf map: %s, err: %v", IngressThrottleStatMapPath, err)
	}

	egressThrottleId, err := ebpf.LoadPinnedMap(EgressThrottleIdMapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return &Tcbpf{}, fmt.Errorf("failed to get bpf map: %s, err: %v", EgressThrottleIdMapPath, err)
	}

	ingressThrottleId, err := ebpf.LoadPinnedMap(IngressThrottleIdMapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return &Tcbpf{}, fmt.Errorf("failed to get bpf map: %s, err: %v", IngressThrottleIdMapPath, err)
	}

	bpfFileName, err := getFileName(EdtBpfProgPath)
	if err != nil {
		return &Tcbpf{}, fmt.Errorf("failed to get bpf name: %v", err)
	}

	Edt = &Tcbpf{
		BpfFileName:            bpfFileName,
		BpfProgPath:            EdtBpfProgPath,
		EgressThrottleCfgMap:   egressThrottleCfg,
		EgressThrottleStatMap:  egressThrottleStat,
		IngressThrottleCfgMap:  ingressThrottleCfg,
		IngressThrottleStatMap: ingressThrottleStat,
		EgressThrottleIdMap:    egressThrottleId,
		IngressThrottleIdMap:   ingressThrottleId,
	}

	return Edt, nil
}

func (e *Tcbpf) SingleWriteEgressThrottleStat(key uint32, value TcEdtThrottleStat) error {
	err := e.EgressThrottleStatMap.Update(key, &value, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("EgressThrottleStatMap Update failed: %v", err)
		return err
	}
	return nil
}

func (e *Tcbpf) SingleReadEgressThrottleStat(key uint32) (TcEdtThrottleStat, error) {
	var value TcEdtThrottleStat

	err := e.EgressThrottleStatMap.Lookup(key, &value)
	if err != nil {
		log.Errorf("EgressThrottleStatMap Lookup failed: %v", err)
		return value, err
	}
	return value, nil
}

// only support array map
func (e *Tcbpf) BatchReadEgressThrottleStat(keys []uint32) ([]TcEdtThrottleStat, error) {
	values := make([]TcEdtThrottleStat, len(keys))

	var cursor ebpf.MapBatchCursor

	_, err := e.EgressThrottleStatMap.BatchLookup(&cursor, keys, values, nil)
	if err != nil {
		log.Errorf("EgressThrottleStatMap BatchLookup failed: %v", err)
		return values, err
	}

	return values, nil
}

func (e *Tcbpf) SingleWriteEgressThrottleCfg(key uint32, value TcEdtThrottleCfg) error {
	err := e.EgressThrottleCfgMap.Update(key, &value, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("EgressThrottleCfgMap Update failed: %v", err)
		return err
	}
	return nil
}

// only support array map
func (e *Tcbpf) BatchWriteEgressThrottleCfg(keys []uint32, values []TcEdtThrottleCfg) error {
	_, err := e.EgressThrottleCfgMap.BatchUpdate(keys, values, &ebpf.BatchOptions{})
	if err != nil {
		log.Errorf("EgressThrottleCfgMap BatchUpdate failed: %v", err)
		return err
	}
	return nil
}

// only support array map
func (e *Tcbpf) BatchReadEgressThrottleCfg(keys []uint32) ([]TcEdtThrottleCfg, error) {
	values := make([]TcEdtThrottleCfg, len(keys))

	var cursor ebpf.MapBatchCursor

	_, err := e.EgressThrottleCfgMap.BatchLookup(&cursor, keys, values, nil)
	if err != nil {
		log.Errorf("EgressThrottleCfgMap BatchLookup failed: %v", err)
		return values, err
	}

	return values, nil
}

func (e *Tcbpf) SingleWriteIngressThrottleStat(key uint32, value TcEdtThrottleStat) error {
	err := e.IngressThrottleStatMap.Update(key, &value, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("IngressThrottleStatMap Update failed: %v", err)
		return err
	}
	return nil
}

func (e *Tcbpf) SingleReadIngressThrottleStat(key uint32) (TcEdtThrottleStat, error) {
	var value TcEdtThrottleStat

	err := e.IngressThrottleStatMap.Lookup(key, &value)
	if err != nil {
		log.Errorf("IngressThrottleStatMap Lookup failed: %v", err)
		return value, err
	}
	return value, nil
}

// only support array map
func (e *Tcbpf) BatchReadIngressThrottleStat(keys []uint32) ([]TcEdtThrottleStat, error) {
	values := make([]TcEdtThrottleStat, len(keys))

	var cursor ebpf.MapBatchCursor

	_, err := e.IngressThrottleStatMap.BatchLookup(&cursor, keys, values, nil)
	if err != nil {
		log.Errorf("IngressThrottleStatMap BatchLookup failed: %v", err)
		return values, err
	}

	return values, nil
}

func (e *Tcbpf) SingleWriteIngressThrottleCfg(key uint32, value TcEdtThrottleCfg) error {
	err := e.IngressThrottleCfgMap.Update(key, &value, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("IngressThrottleCfgMap Update failed: %v", err)
		return err
	}
	return nil
}

// only support array map
func (e *Tcbpf) BatchWriteIngressThrottleCfg(keys []uint32, values []TcEdtThrottleCfg) error {
	_, err := e.IngressThrottleCfgMap.BatchUpdate(keys, values, &ebpf.BatchOptions{})
	if err != nil {
		log.Errorf("IngressThrottleCfgMap BatchUpdate failed: %v", err)
		return err
	}
	return nil
}

// only support array map
func (e *Tcbpf) BatchReadIngressThrottleCfg(keys []uint32) ([]TcEdtThrottleCfg, error) {
	values := make([]TcEdtThrottleCfg, len(keys))

	var cursor ebpf.MapBatchCursor

	_, err := e.IngressThrottleCfgMap.BatchLookup(&cursor, keys, values, nil)
	if err != nil {
		log.Errorf("IngressThrottleCfgMap BatchLookup failed: %v", err)
		return values, err
	}

	return values, nil
}

func (e *Tcbpf) UpdateEgressThrottleId(key TcEdtIdKey, value uint32) error {
	err := e.EgressThrottleIdMap.Update(key, &value, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("EgressThrottleIdMap Update failed: %v", err)
		return err
	}
	return nil
}

func (e *Tcbpf) DeleteEgressThrottleId(key TcEdtIdKey) error {
	err := e.EgressThrottleIdMap.Delete(key)
	if err != nil {
		log.Errorf("EgressThrottleIdMap Delete failed: %v", err)
		return err
	}
	return nil
}

func (e *Tcbpf) UpdateIngressThrottleId(key TcEdtIdKey, value uint32) error {
	err := e.IngressThrottleIdMap.Update(key, &value, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("IngressThrottleIdMap Update failed: %v", err)
		return err
	}
	return nil
}

func (e *Tcbpf) DeleteIngressThrottleId(key TcEdtIdKey) error {
	err := e.IngressThrottleIdMap.Delete(key)
	if err != nil {
		log.Errorf("IngressThrottleIdMap Delete failed: %v", err)
		return err
	}
	return nil
}

func (e *Tcbpf) Close() {
	e.EgressThrottleStatMap.Close()
	e.EgressThrottleCfgMap.Close()
	e.IngressThrottleStatMap.Close()
	e.IngressThrottleCfgMap.Close()
	e.EgressThrottleIdMap.Close()
	e.IngressThrottleIdMap.Close()
}

func (e *Tcbpf) AddEgressConfig(id uint32, egressConfig common.QosConfig) {
	var egressThrottleCfg TcEdtThrottleCfg

	egressThrottleCfg.Priority = egressConfig.Priority
	egressThrottleCfg.Interval = uint32(time.Duration(PeriodInterval) * time.Millisecond)
	if egressConfig.BandWidthRequestM == 0 {
		egressConfig.BandWidthRequestM = 10 // 10Mb, set a minimum initial rate used in bpf prog
	}
	egressThrottleCfg.LowRate = egressConfig.BandWidthRequestM * PerMB
	egressThrottleCfg.HighRate = egressConfig.BandWidthLimitM * PerMB
	egressThrottleCfg.ReqRate = egressConfig.BandWidthRequestM * PerMB

	e.SingleWriteEgressThrottleCfg(id, egressThrottleCfg)
	log.Infof("Add egress config, id: %d, %+v", id, egressThrottleCfg)
}

func (e *Tcbpf) AddIngressConfig(id uint32, ingressConfig common.QosConfig) {
	var ingressThrottleCfg TcEdtThrottleCfg

	ingressThrottleCfg.Priority = ingressConfig.Priority
	ingressThrottleCfg.Interval = uint32(time.Duration(PeriodInterval) * time.Millisecond)
	if ingressConfig.BandWidthRequestM == 0 {
		ingressConfig.BandWidthRequestM = 10 // 10Mb, set a minimum initial rate used in bpf prog
	}
	ingressThrottleCfg.LowRate = ingressConfig.BandWidthRequestM * PerMB
	ingressThrottleCfg.HighRate = ingressConfig.BandWidthLimitM * PerMB
	ingressThrottleCfg.ReqRate = ingressConfig.BandWidthRequestM * PerMB

	e.SingleWriteIngressThrottleCfg(id, ingressThrottleCfg)
	log.Infof("Add ingress config, id: %d, %+v", id, ingressThrottleCfg)
}
