package main

import (
	"context"
	"fmt"
	algproc "oncn-bwm/cmd/alg-daemon/algproc"
	"oncn-bwm/cmd/daemon/common"
	bpf "oncn-bwm/pkg/bpfgo"
	"oncn-bwm/pkg/tc"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	DefaultInterval = 50  // 带宽调整的周期间隔
	DefaultPercent  = 10  // 默认流量的带宽设为占总带宽的1/DefaultPercent
	DefaultRatio    = 0.7 // 以DefaultRatio为比例作为带宽调大和调小的参考依据
	DefaultPace     = 10  // 每次调整带宽的1/DefaultPace
	IfbName         = "bwmifb0"
	MinBandwidth    = 10                // 每个实例调整后的请求带宽不能小于MinBandwidth MB
	PerMB           = (1024 * 1024 / 8) // 1MB = 1024 * 1024 / 8 Byte
)

func init() {
	if tc.Custom == "DAHUA" {
		script := "/usr/share/bwm/custominit.sh"
		cmd := exec.Command(script, tc.Custom)
		output, err := cmd.CombinedOutput()
		if err != nil {
			exitCode := 0
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
			panic(fmt.Sprintf("custominit.sh %s, err: %s, exitcode:%d", tc.Custom, output, exitCode))
		}
		// 修改ip_forward_update_priority参数
		value := []byte("0\n")
		err = os.WriteFile("/proc/sys/net/ipv4/ip_forward_update_priority", value, 0644)
		if err != nil {
			panic(fmt.Sprintf("write ip_forward_update_priority err: %v", err))
		}
	}
}

func runAlg(ctx context.Context, errChan chan<- error) {
	var err error = nil
	defer func() {
		errChan <- err
	}()
	//获取默认路由所在网卡及其速度
	HostNICName, err := common.GetMasterIntf()
	if err != nil {
		err = errors.Errorf("get host NIC failed, err: %v", err)
		return
	}
	//获取网卡速度
	hostNICSpeed, err := common.GetNetworkInterfaceSpeed(HostNICName)
	if err != nil {
		log.Warnf("can't get host NIC %s speed, err: %v", HostNICName, err)
		speed := os.Getenv("HostNICSpeed")
		if speed != "" {
			speedInt, err := strconv.Atoi(speed)
			if err != nil {
				err = errors.Wrapf(err, "convert HostNICSpeed string:%v to int type failed, err: %v", speed, err)
				return
			}
			hostNICSpeed = uint64(speedInt)
		} else {
			err = errors.Wrapf(err, "host NIC %s speed not set, err: %v", HostNICName, err)
			return
		}
	}
	log.Infof("host NIC %s speed %d", HostNICName, hostNICSpeed)

	intervalInt := DefaultInterval
	interval := os.Getenv("BwAdjustInterval")
	if interval != "" {
		intervalInt, err = strconv.Atoi(interval)
		if err != nil {
			err = errors.Wrapf(err, "convert BwAdjustInterval string:%v to int type failed, err: %v", interval, err)
			return
		}
		if intervalInt < 20 || intervalInt > 1000 {
			log.Warnf("the setting value:%v of bandwidth adjust interval is invalid, use the default value:%v", intervalInt, DefaultInterval)
			intervalInt = DefaultInterval
		}
	}

	// enable egress qos
	err = bpf.EnableDevQos(HostNICName, "", bpf.EgressBpfSection)
	if err != nil {
		err = errors.Wrapf(err, "enable dev %s Qos failed, err: %v", HostNICName, err)
		return
	}
	defer func() {
		if err := bpf.DisableDevQos(HostNICName, "", bpf.EgressBpfSection); err != nil {
			log.Errorf("disable %s ebpf Qos failed, err: %v", HostNICName, err)
		}
		log.Infof("disable egress Qos")
	}()

	err = tc.EnableIngressQos(HostNICName, IfbName)
	if err != nil {
		err = errors.Wrapf(err, "EnableIngressQos failed, err: %v", err)
		return
	}

	defer func() {
		if err := tc.DisableIngressQos(HostNICName, IfbName); err != nil {
			log.Errorf("DisableIngressQos failed, err: %v", err)
		}
		log.Infof("disable ingress Qos")
	}()

	edtBpf, err := bpf.NewTcbpf()
	if err != nil {
		err = errors.Wrapf(err, "init edtBpf failed, err: %v", err)
		return
	}
	defer func() {
		edtBpf.Close()
	}()

	totalBandWidth := hostNICSpeed * 1024 * 1024 / 8 //  Mb -> Byte
	DaemonProcess := algproc.NewDaemonProc(totalBandWidth, totalBandWidth, uint32(intervalInt), edtBpf)

	percentInt := DefaultPercent
	percent := os.Getenv("DefaultFlowBwPercent")
	if percent != "" {
		percentInt, err = strconv.Atoi(percent)
		if err != nil {
			err = errors.Wrapf(err, "convert DefaultFlowBwPercent string:%v to int type failed, err: %v", percent, err)
			return
		}
		if percentInt <= 0 || percentInt > 50 {
			log.Warnf("the setting value:%v of default flow percent is invalid, use the default value:%v", percentInt, DefaultPercent)
			percentInt = DefaultPercent
		}
	}

	DefaultFlowConfig := common.QosConfig{
		BandWidthRequestM: hostNICSpeed / uint64(percentInt),
		BandWidthLimitM:   hostNICSpeed,
		Priority:          0,
	}

	edtBpf.AddIngressConfig(0, DefaultFlowConfig)
	edtBpf.AddEgressConfig(0, DefaultFlowConfig)

	minBandwidthInt, err := getEnvIntVar("MinBandwidth", MinBandwidth, 1, 50)
	if err != nil {
		return
	}

	paceInt, err := getEnvIntVar("BwAdjustPace", DefaultPace, 0, 50)
	if err != nil {
		return
	}

	ratioFloat, err := getEnvFloatVar("BwReferRatio", DefaultRatio, 0.5, 0.9)
	if err != nil {
		return
	}

	MinBandwidthByte := minBandwidthInt * PerMB
	go DaemonProcess.Run("egress", uint64(MinBandwidthByte), paceInt, ratioFloat)
	go DaemonProcess.Run("ingress", uint64(MinBandwidthByte), paceInt, ratioFloat)
	log.Info("alg-daemon start")
	for {
		select {
		case <-ctx.Done():
			log.Errorf("runAlg goroutine exiting...")
			err = errors.New("receive cancel ctx")
			return
		}
	}
}

func getEnvIntVar(name string, defaultValue int, minValue int, maxValue int) (int, error) {
	value := os.Getenv(name)
	if value != "" {
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return 0, errors.Wrapf(err, "convert %s string:%v to int type failed, err: %v", name, value, err)
		}
		if intVal < minValue || intVal > maxValue {
			log.Warnf("the setting value:%v of %s is invalid, valid range is (%d, %d], use the default value:%v", intVal, name, minValue, maxValue, defaultValue)
			return defaultValue, nil
		}
		return intVal, nil
	}
	return defaultValue, nil
}

func getEnvFloatVar(name string, defaultValue float64, minValue float64, maxValue float64) (float64, error) {
	value := os.Getenv(name)
	if value != "" {
		floatVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return 0, errors.Wrapf(err, "convert %s string:%v to float type failed, err: %v", name, value, err)
		}
		if floatVal < minValue || floatVal > maxValue {
			log.Warnf("the setting value:%v of %s is invalid, valid range is (%f, %f], use the default value:%v", floatVal, name, minValue, maxValue, defaultValue)
			return defaultValue, nil
		}
		return floatVal, nil
	}
	return defaultValue, nil
}

func main() {
	log.SetLevel(log.InfoLevel)

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go runAlg(ctx, errChan)
	//处理信号
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGABRT, syscall.SIGTSTP)
	for {
		select {
		case sig := <-sigs:
			log.Errorf("receive sigs %v", sig)
			cancel()
		case err := <-errChan:
			log.Errorf("alg err %+v", err)
			return
		}
	}
}
