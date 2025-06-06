//go:build DAHUA
// +build DAHUA

package bpf

type TcEdtIdKey struct {
        Ip   uint32
        Port uint32
}

type TcEdtThrottleCfg struct {
        Priority uint32
        Interval uint32
        LowRate  uint64
        HighRate uint64
        ReqRate  uint64
}

type TcEdtThrottleStat struct {
        T_last    uint64
        T_start   uint64
        Rate      uint64
        TxBytes   uint64
        TotalPkts uint64
}

