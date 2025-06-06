package algproc

import (
	bpf "oncn-bwm/pkg/bpfgo"
	"time"

	log "github.com/sirupsen/logrus"
)

var DaemonProcess *DaemonProc

const (
	MaxObjSize = 5000 // same with MAX_MAP_SIZE
)

const (
	DownReqRate      = 0
	NeedReachLowRate = 1
	ReachedLowRate   = 2

	AllReachedLowRate    = 1
	NotAllReachedLowRate = 0
)

type EdtProcData struct {
	ThrottleCfg  []bpf.TcEdtThrottleCfg
	ThrottleStat []bpf.TcEdtThrottleStat
	IDs          []uint32
	ObjStatus    []uint8
	ValidObjCnt  uint32
	TotalBw      uint64
}

type DaemonProc struct {
	EgressDataEntry  EdtProcData
	IngressDataEntry EdtProcData
	EbpfEdt          *bpf.Tcbpf
	Interval         uint32
}

func NewDaemonProc(egressTotalBw uint64, ingressTotalBw uint64, interval uint32, ebpfEdt *bpf.Tcbpf) *DaemonProc {
	return &DaemonProc{
		EgressDataEntry: EdtProcData{
			ThrottleCfg:  make([]bpf.TcEdtThrottleCfg, MaxObjSize),
			ThrottleStat: make([]bpf.TcEdtThrottleStat, MaxObjSize),
			IDs:          make([]uint32, MaxObjSize),
			ObjStatus:    make([]uint8, MaxObjSize),
			ValidObjCnt:  0,
			TotalBw:      egressTotalBw,
		},
		IngressDataEntry: EdtProcData{
			ThrottleCfg:  make([]bpf.TcEdtThrottleCfg, MaxObjSize),
			ThrottleStat: make([]bpf.TcEdtThrottleStat, MaxObjSize),
			IDs:          make([]uint32, MaxObjSize),
			ObjStatus:    make([]uint8, MaxObjSize),
			ValidObjCnt:  0,
			TotalBw:      ingressTotalBw,
		},

		EbpfEdt:  ebpfEdt,
		Interval: interval,
	}
}

func Clip(val, min, max uint64) uint64 {
	if val < min {
		return min
	} else if val > max {
		return max
	}
	return val
}

func (d *DaemonProc) lookupEdtProcData(direction string) (*EdtProcData, error) {
	var (
		err      error
		stats    []bpf.TcEdtThrottleStat
		cfgs     []bpf.TcEdtThrottleCfg
		procData *EdtProcData
	)

	if direction == "egress" {
		procData = &d.EgressDataEntry
		stats, err = d.EbpfEdt.BatchReadEgressThrottleStat(procData.IDs)
		if err != nil {
			log.Errorf("BatchReadEgressThrottleStat failed, err: %v", err)
			return nil, err
		}

		cfgs, err = d.EbpfEdt.BatchReadEgressThrottleCfg(procData.IDs)
		if err != nil {
			log.Errorf("BatchReadEgressThrottleCfg failed, err: %v", err)
			return nil, err
		}

	} else if direction == "ingress" {
		procData = &d.IngressDataEntry
		stats, err = d.EbpfEdt.BatchReadIngressThrottleStat(procData.IDs)
		if err != nil {
			log.Errorf("BatchReadIngressThrottleStat failed, err: %v", err)
			return nil, err
		}

		cfgs, err = d.EbpfEdt.BatchReadIngressThrottleCfg(procData.IDs)
		if err != nil {
			log.Errorf("BatchReadIngressThrottleCfg failed, err: %v", err)
			return nil, err
		}
	}

	procData.ValidObjCnt = 0
	for index, stat := range stats {
		if stat.T_start != 0 && procData.ThrottleStat[index].T_start == stat.T_start {
			log.Debugf("d.ThrottleStat[%d].T_start: %d, stat.T_start: %d", index, procData.ThrottleStat[index].T_start, stat.T_start)
			stat.Rate = 0
		}

		procData.ThrottleStat[index] = stat
		procData.ThrottleCfg[index] = cfgs[index]
		if stat.Rate > 0 {
			procData.ObjStatus[index] = 1 // 置1表示该对象当前有流量
			procData.ValidObjCnt++
		} else {
			procData.ObjStatus[index] = 0 // 置0表示该对象当前没有流量
		}
	}

	return procData, nil
}

func (d *DaemonProc) updateThrottleCfg(procData *EdtProcData, direction string) {
	if direction == "egress" {
		d.EbpfEdt.BatchWriteEgressThrottleCfg(procData.IDs, procData.ThrottleCfg)
	} else if direction == "ingress" {
		d.EbpfEdt.BatchWriteIngressThrottleCfg(procData.IDs, procData.ThrottleCfg)
	}
}

func (d *DaemonProc) Run(direction string, minBandwidth uint64, pace int, ratio float64) error {
	allocMinRate := func(id int, curRate uint64, reqRate uint64, lowRate uint64) (uint64, uint8) {
		// state用来标识流量状态，用于后续判断pod是否需要再分配流量;
		// 默认0: 流量处于下降状态;
		// 1：业务带宽还未达到最低请求带宽，需要提升；
		// 2：业务带宽也达到最低请求带宽，所有业务流量都达到该状态时按优先级分配剩余带宽
		var (
			newReqRate uint64 = curRate
			state      uint8  = 0
		)
		cur_f := float64(curRate)
		req_f := float64(reqRate)

		if cur_f < req_f*ratio {
			// 小，则减少
			newReqRate = reqRate
			deltaBw := int64((reqRate) / uint64(pace))
			newReqRate -= uint64(deltaBw)
			if id > 0 {
				log.Infof("%v: id %d enter down req rate, DownReqRate state, curRate: %d, reqRate: %d, newReqRate: %d, lowRate: %d", direction, id, curRate, reqRate, newReqRate, lowRate)
			}

			// 当new_rate = curRate时，可能存在curRate突然很小，而reqRate的十分之一，即deltaBw却很大，
			// 会导致相减之后的结果为负，从而无符号数溢出变为很大的值
			// deltaBw := int64((reqRate) / uint64(adjustGain))
			// new_rate -= uint64(deltaBw)

			// 无任何配置的pod会默认分配最低请求带宽10mb，而如果流量突然变低走到down逻辑,
			// 这里Clip会使得newReqRate被设置为MinBandwidth,后面很难再提升上去
			//newReqRate = Clip(newReqRate, MinBandwidth, lowRate)

			newReqRate = Clip(newReqRate, minBandwidth, newReqRate)
		} else {
			// 大，则增大，但是只增大到最低请求带宽，并且根据是否达到最低请求带宽设置当前流量状态
			deltaBw := int64((reqRate) / uint64(pace))
			newReqRate += uint64(deltaBw)
			newReqRate = Clip(newReqRate, minBandwidth, lowRate)

			if newReqRate < lowRate {
				log.Infof("%v: id %d enter up req rate, NeedReachLowRate state, curRate: %d, reqRate: %d, newReqRate: %d, lowRate: %d", direction, id, curRate, reqRate, newReqRate, lowRate)
				state = NeedReachLowRate
			} else if newReqRate >= lowRate {
				log.Infof("%v: id %d enter up req rate, ReachedLowRate state, curRate: %d, reqRate: %d, newReqRate: %d, lowRate: %d", direction, id, curRate, reqRate, newReqRate, lowRate)
				state = ReachedLowRate
			}
		}

		return newReqRate, state
	}

	for {
		procData, err := d.lookupEdtProcData(direction)

		if err != nil {
			log.Errorf("lookupEdtProcData failed, err: %v", err)
			continue
		}

		remainBw := int64(procData.TotalBw)
		PriorityAllocPercent := []uint16{
			0: 10,
			1: 20,
			2: 70,
		}

		priorityCnt := []uint16{
			0: 0, // low priority
			1: 0, // mid priority
			2: 0, // high priority
		}
		lowRateReachCnt := 0
		DownReqRateCnt := 0
		AllObjStatus := NotAllReachedLowRate

		log.Infof("%v: *****************************************", direction)
		//t3 := time.Now().UnixNano()
		for id, stats := range procData.ThrottleStat {
			if procData.ObjStatus[id] == 1 { // 只有有流量的pod的才会被计算
				// 经过allocMinRate函数处理之后ObjStatus的含义不再是有无流量，而是当前pod带宽的状态，具体见allocMinRate中state的含义
				procData.ThrottleCfg[id].ReqRate, procData.ObjStatus[id] = allocMinRate(id, stats.Rate, procData.ThrottleCfg[id].ReqRate, procData.ThrottleCfg[id].LowRate)
				remainBw -= int64(procData.ThrottleCfg[id].ReqRate)

				if procData.ObjStatus[id] == NeedReachLowRate { // 表明还未达到最低请求带宽，需要进行平均分配
					priorityCnt[procData.ThrottleCfg[id].Priority] += 1 // 记录达到最低请求带宽后可被进一步分配带宽的pod的统计，相应优先级计数+1
				} else if procData.ObjStatus[id] == ReachedLowRate {
					lowRateReachCnt++
					priorityCnt[procData.ThrottleCfg[id].Priority] += 1 // 记录达到最低请求带宽后可被进一步分配带宽的pod的统计，相应优先级计数+1
				} else if procData.ObjStatus[id] == DownReqRate { // 统计带宽下降状态的pod数量
					DownReqRateCnt++
				}
			}
		}

		// 所有有效pod都达到最低请求带宽 或者 下降状态pod数+已达到最低请求带宽的pod数刚好等于有效pod数
		if lowRateReachCnt == int(procData.ValidObjCnt) || (lowRateReachCnt+DownReqRateCnt) == int(procData.ValidObjCnt) {
			log.Infof("%v: all valid pod reach lowrate", direction)
			AllObjStatus = AllReachedLowRate
		} else if lowRateReachCnt < int(procData.ValidObjCnt) {
			log.Infof("%v: not all valid pod reach lowrate", direction)
			AllObjStatus = NotAllReachedLowRate
		}

		log.Infof("%v: DownReqRateCnt: %d, lowRateReachCnt: %d, ValidObjCnt: %d", direction, DownReqRateCnt, lowRateReachCnt, int(procData.ValidObjCnt))

		var allocDivide int64 = 0 // 分配剩余带宽时的比例分母
		for prio, count := range priorityCnt {
			if count > 0 { // 该优先级存在有效pod，对应的分配比例才会累加到分母中
				allocDivide += int64(PriorityAllocPercent[prio])
			}
		}

		log.Infof("%v: =========================================", direction)
		remainBwVary := remainBw
		for id, _ := range procData.ThrottleStat {
			// 对于配置了很高的请求带宽，但实际流量很小的实例，在这里进行限制，使其不参与流量再分配, 每次只涨reqRate的10%（第一轮分配）。
			// 引入0.7比例系数降低不参与带宽再分配的概率，对出入方向同时开启场景时的带宽波动有比较明显的效果（出方向流量收到的ack也需要更快接收，才能使得发包带宽稳定）。
			if procData.ObjStatus[id] == NeedReachLowRate && procData.ThrottleStat[id].Rate < procData.ThrottleCfg[id].ReqRate*7/10 {
				log.Infof("%v: 0000 id: %d, CurRate: %d, ReqRate: %d", direction, id, procData.ThrottleStat[id].Rate, procData.ThrottleCfg[id].ReqRate)
				priorityCnt[procData.ThrottleCfg[id].Priority] -= 1
				lowRateReachCnt++
				if lowRateReachCnt == int(procData.ValidObjCnt) || (lowRateReachCnt+DownReqRateCnt) == int(procData.ValidObjCnt) {
					log.Infof("%v: all valid pod reach lowrate", direction)
					AllObjStatus = AllReachedLowRate
				}
				continue
			}

			if remainBw > 0 && procData.ObjStatus[id] == NeedReachLowRate && AllObjStatus == NotAllReachedLowRate {
				log.Infof("%v: 1111 id: %d, remainBw: %d, equal division count: %d", direction, id, remainBw, procData.ValidObjCnt-uint32(lowRateReachCnt)-uint32(DownReqRateCnt))
				deltaBw := int64((remainBw)/int64(procData.ValidObjCnt-uint32(lowRateReachCnt)-uint32(DownReqRateCnt))) + 1 // 加1向上取整
				remainBwVary -= deltaBw                                                                                     // remainBw减为小于0可提前跳出循环
				procData.ThrottleCfg[id].ReqRate += uint64(deltaBw)
			}

			if AllObjStatus == AllReachedLowRate && remainBw > 0 && procData.ObjStatus[id] == ReachedLowRate {
				thisPrio := procData.ThrottleCfg[id].Priority
				log.Infof("%v: 2222 id: %d, remainBw: %d, PriorityARate: %d, allocDivide: %d, CountPrio: %d", direction, id, remainBw, PriorityAllocPercent[thisPrio], allocDivide, priorityCnt[thisPrio])
				deltaBw := int64(((remainBw)*int64(PriorityAllocPercent[thisPrio])/allocDivide)/int64(priorityCnt[thisPrio])) + 1
				remainBwVary -= deltaBw // remainBw减为小于0可提前跳出循环
				procData.ThrottleCfg[id].ReqRate += uint64(deltaBw)
			}

			if procData.ThrottleStat[id].Rate > 0 {
				log.Infof("%v: after remainBw realloc, remainBwVary: %d, id: %d, CurRate: %d, ReqRate: %d LowRate: %d", direction, remainBwVary, id, procData.ThrottleStat[id].Rate, procData.ThrottleCfg[id].ReqRate, procData.ThrottleCfg[id].LowRate)
			}
			if remainBwVary <= 0 {
				goto END
			}
		}

	END:
		d.updateThrottleCfg(procData, direction)
		time.Sleep(time.Duration(d.Interval) * time.Millisecond)
	}
}
