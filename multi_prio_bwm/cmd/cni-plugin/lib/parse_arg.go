package lib

import (
	"encoding/json"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

type NetConf struct {
	types.NetConf

	Log_level string `json:"log_level"` //日志等级
}

type ArgsSpec struct {
	types.CommonArgs
	K8S_POD_NAME      types.UnmarshallableString
	K8S_POD_NAMESPACE types.UnmarshallableString
}

func parsePrevResult(n *NetConf) (*NetConf, error) {
	if n.RawPrevResult != nil {
		resultBytes, err := json.Marshal(n.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(n.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		n.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	return n, nil
}

func loadNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %s", err)
	}

	return parsePrevResult(n)
}

func ParseArgs(args *skel.CmdArgs) (*NetConf, *current.Result, *ArgsSpec, error) {
	// 解析配置文件/etc/cni/net.d/中的配置文件
	n, err := loadNetConf(args.StdinData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to parse CNI configuration \"%s\": %v", args.StdinData, err)
	}

	err = version.ParsePrevResult(&n.NetConf)
	if err != nil {
		err = fmt.Errorf("unable to understand network config: %v", err)
		return nil, nil, nil, err
	}

	// 解析调用该插件之前的cni插件传递的参数Pre Result
	var prevRes *current.Result
	if n.PrevResult != nil {
		prevRes, err = current.NewResultFromResult(n.NetConf.PrevResult)
		if err != nil {
			err = fmt.Errorf("unable to get previous network result: %v", err)
			return nil, nil, nil, err
		}
	}
	// 解析pod pause容器相关参数
	cniArgs := &ArgsSpec{}
	if err = types.LoadArgs(args.Args, cniArgs); err != nil {
		err = fmt.Errorf("unable to extract CNI arguments: %v", err)
		return nil, nil, nil, err
	}

	return n, prevRes, cniArgs, nil
}
