// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// LoadTcEdt returns the embedded CollectionSpec for TcEdt.
func LoadTcEdt() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TcEdtBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load TcEdt: %w", err)
	}

	return spec, err
}

// LoadTcEdtObjects loads TcEdt and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*TcEdtObjects
//	*TcEdtPrograms
//	*TcEdtMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadTcEdtObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadTcEdt()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// TcEdtSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TcEdtSpecs struct {
	TcEdtProgramSpecs
	TcEdtMapSpecs
}

// TcEdtSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TcEdtProgramSpecs struct {
	BwmTcEgress  *ebpf.ProgramSpec `ebpf:"bwm_tc_egress"`
	BwmTcIngress *ebpf.ProgramSpec `ebpf:"bwm_tc_ingress"`
}

// TcEdtMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TcEdtMapSpecs struct {
	EgressCfg   *ebpf.MapSpec `ebpf:"egress_cfg"`
	EgressId    *ebpf.MapSpec `ebpf:"egress_id"`
	EgressStat  *ebpf.MapSpec `ebpf:"egress_stat"`
	IngressCfg  *ebpf.MapSpec `ebpf:"ingress_cfg"`
	IngressId   *ebpf.MapSpec `ebpf:"ingress_id"`
	IngressStat *ebpf.MapSpec `ebpf:"ingress_stat"`
}

// TcEdtObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadTcEdtObjects or ebpf.CollectionSpec.LoadAndAssign.
type TcEdtObjects struct {
	TcEdtPrograms
	TcEdtMaps
}

func (o *TcEdtObjects) Close() error {
	return _TcEdtClose(
		&o.TcEdtPrograms,
		&o.TcEdtMaps,
	)
}

// TcEdtMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadTcEdtObjects or ebpf.CollectionSpec.LoadAndAssign.
type TcEdtMaps struct {
	EgressCfg   *ebpf.Map `ebpf:"egress_cfg"`
	EgressId    *ebpf.Map `ebpf:"egress_id"`
	EgressStat  *ebpf.Map `ebpf:"egress_stat"`
	IngressCfg  *ebpf.Map `ebpf:"ingress_cfg"`
	IngressId   *ebpf.Map `ebpf:"ingress_id"`
	IngressStat *ebpf.Map `ebpf:"ingress_stat"`
}

func (m *TcEdtMaps) Close() error {
	return _TcEdtClose(
		m.EgressCfg,
		m.EgressId,
		m.EgressStat,
		m.IngressCfg,
		m.IngressId,
		m.IngressStat,
	)
}

// TcEdtPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadTcEdtObjects or ebpf.CollectionSpec.LoadAndAssign.
type TcEdtPrograms struct {
	BwmTcEgress  *ebpf.Program `ebpf:"bwm_tc_egress"`
	BwmTcIngress *ebpf.Program `ebpf:"bwm_tc_ingress"`
}

func (p *TcEdtPrograms) Close() error {
	return _TcEdtClose(
		p.BwmTcEgress,
		p.BwmTcIngress,
	)
}

func _TcEdtClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tcedt_bpfel.o
var _TcEdtBytes []byte
