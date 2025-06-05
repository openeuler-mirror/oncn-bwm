package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	daemon_rpc "oncn-bwm/api/v1"
	"oncn-bwm/cmd/cmdctl/lib"
	"oncn-bwm/cmd/daemon/common"
	"oncn-bwm/pkg/nets"
	"oncn-bwm/pkg/rpc"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func convertBigEndianPortToLittle(big uint32) uint32 {
	tmp := make([]byte, 2)
	big16 := uint16(big)
	binary.LittleEndian.PutUint16(tmp, big16)
	little16 := binary.BigEndian.Uint16(tmp)
	return uint32(little16)
}

func main() {
	rpcClient, closeConn, err := rpc.NewNetQosRpcClient()
	if err != nil {
		err = fmt.Errorf("new rpc client err: %v", err)
		panic(err.Error())
	}
	defer closeConn()
	//bwmctl podinfo list
	//bwmctl specflow list
	var cmdList = &cobra.Command{
		Use:   "list [command]",
		Short: "List resources",
		Long:  `List specific resources, either podinfo or specflow.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "podinfo":
				podInfos, err := rpcClient.ListQosPodInfo(context.TODO(), &daemon_rpc.EmptyRequest{})
				if err != nil {
					err = fmt.Errorf("list podinfo err : %v", err)
					return err
				}
				for _, podInfo := range podInfos.GetPodInfos() {
					podInfoJSON, err := json.MarshalIndent(podInfo, "", "  ")
					if err != nil {
						return fmt.Errorf("marshal json err: %v", err)
					}
					fmt.Println(string(podInfoJSON))
				}
			case "specflow":
				qosFlows, err := rpcClient.ListQosFlow(context.TODO(), &daemon_rpc.EmptyRequest{})
				if err != nil {
					err = fmt.Errorf("list specflow err : %v", err)
					return err
				}
				for _, qosFlow := range qosFlows.GetQosFlows() {
					qosFlow.Port = convertBigEndianPortToLittle(qosFlow.Port)
					qosFlowJSON, err := json.MarshalIndent(qosFlow, "", "  ")
					if err != nil {
						return fmt.Errorf("marshal json err: %v", err)
					}
					fmt.Println(string(qosFlowJSON))
				}
			default:
				return fmt.Errorf("invalid command arg for list: must be 'podinfo' or 'specflow'")
			}
			return nil
		},
	}

	//bwmctl set egress 192.168.1.1:33333 2 100 500
	var cmdSet = &cobra.Command{
		Use:   "set [direction] [ip:port] [priority] [req_bandwidth] [limit_bandwidth]",
		Short: "Set specflow",
		Long:  `Set specflow with 'direction ip:port priority request_bandwidth limit_bandwidth'`,
		Args:  cobra.MinimumNArgs(5),
		RunE: func(cmd *cobra.Command, args []string) error {
			direction := args[0]
			ipaddr := args[1]
			priority := args[2]
			reqBandwidth := args[3]
			limitBandwidth := args[4]

			if direction != "egress" && direction != "ingress" {
				return fmt.Errorf("Invalid direction value, can only be \"egress\" or \"ingress\"")
			}

			var (
				ip     string
				port   int
				config = &common.QosConfig{}
			)

			index := strings.LastIndex(ipaddr, ":")
			if index != -1 {
				ip = ipaddr[:index]
				portStr := ipaddr[index+1:]
				port, err = strconv.Atoi(portStr)
				if err != nil {
					return fmt.Errorf("Invalid value, port:%s must be an integer\n", portStr)
				}
			} else {
				return fmt.Errorf("Invalid ip addr: %s", ipaddr)
			}

			if config, err = lib.ConvertConfig(priority, reqBandwidth, limitBandwidth); err != nil {
				return fmt.Errorf("convertConfig failed, err: %v\n", err)
			}

			req := &daemon_rpc.QosFlow{
				Direct: direction,
				Ip:     ip,
				Port:   nets.ConvertPortToBigEndian(uint32(port)),
			}

			if direction == "egress" {
				req.SendPriority = config.Priority
				req.SendBandWidthRequestM = config.BandWidthRequestM
				req.SendBandWidthLimitM = config.BandWidthLimitM
			} else if direction == "ingress" {
				req.RecvPriority = uint32(config.Priority)
				req.RecvBandWidthRequestM = uint64(config.BandWidthRequestM)
				req.RecvBandWidthLimitM = uint64(config.BandWidthLimitM)
			}

			rep, err := rpcClient.SetFlowRequest(req)
			if err != nil {
				return fmt.Errorf("rpc setflow err: %v", err)
			}
			if false == rep.GetSuccess() {
				return fmt.Errorf("rpc setflow fail, reason: %s", rep.FailReason)
			}
			fmt.Printf("set flow %s %s %d success\n", direction, ip, port)
			return nil
		},
	}
	//bwmctl unset egress 192.168.1.1:33333
	var cmdUnSet = &cobra.Command{
		Use:   "unset [direction] [ip:port]",
		Short: "Unset specflow",
		Long:  `Unset specflow with 'direction ip:port'`,
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			direction := args[0]
			ipaddr := args[1]
			if direction != "egress" && direction != "ingress" {
				return fmt.Errorf("Invalid direction value, can only be \"egress\" or \"ingress\"")
			}

			var (
				ip   string
				port int
			)

			index := strings.LastIndex(ipaddr, ":")
			if index != -1 {
				ip = ipaddr[:index]
				portStr := ipaddr[index+1:]
				port, err = strconv.Atoi(portStr)
				if err != nil {
					return fmt.Errorf("Invalid value, port:%s must be an integer\n", portStr)
				}
			} else {
				return fmt.Errorf("Invalid ip addr: %s", ipaddr)
			}

			req := &daemon_rpc.QosFlow{
				Direct: direction,
				Ip:     ip,
				Port:   nets.ConvertPortToBigEndian(uint32(port)),
			}
			rep, err := rpcClient.UnSetFlowRequest(req)
			if err != nil {
				return fmt.Errorf("rpc unsetflow err: %v", err)
			}
			if false == rep.GetSuccess() {
				return fmt.Errorf("rpc unsetflow fail, reason: %s", rep.FailReason)
			}
			fmt.Printf("unset flow %s %s %d success\n", direction, ip, port)
			return nil
		},
	}
	var rootCmd = &cobra.Command{Use: "list and set daemonproc data"}
	rootCmd.AddCommand(cmdList, cmdSet, cmdUnSet)
	if err := rootCmd.Execute(); err != nil {
		err = fmt.Errorf("exec err: %v", err)
		panic(err.Error())
	}
}
