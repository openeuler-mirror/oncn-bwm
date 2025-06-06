package main

import (
	"encoding/json"
	"flag"
	"fmt"
	bpf "oncn-bwm/daemon/bpfgo"
	"oncn-bwm/daemon/common"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func isVirtualDevice(deviceName string) bool {
	return deviceName == "lo" || deviceName == "veth"
}

// 获取所有网卡设备名
func GetAllNetworkDevices() ([]string, error) {
	var devices []string

	files, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		// Exclude loopback and virtual devices
		if !file.IsDir() && !isVirtualDevice(file.Name()) {
			devices = append(devices, file.Name())
		}
	}

	return devices, nil
}

func IsInterfaceExists(interfaceName string) (bool, error) {
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", interfaceName))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ContainerConfig 结构定义了配置文件中的数据结构
type ContainerConfig struct {
	Id                    int    `json:"id"`  // pod id
	UID                   string `json:"uid"` // container uid, for cgroup path concat
	SendPriority          int    `json:"prio"`
	SendBandWidthRequestM int    `json:"bw"`
}

// ReadConfig 从指定的配置文件路径读取配置信息
func ReadConfig(filePath string) ([]ContainerConfig, error) {
	var configs []ContainerConfig

	// 读取配置文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Parse the configuration file content
	err = json.Unmarshal(data, &configs)
	if err != nil {
		return nil, err
	}

	return configs, nil
}

// extractPIDsFromLsnsOutput takes the output of `lsns -t net` as input and extracts all PIDs.
func extractPIDsFromLsnsOutput(lsnsOutput string) ([]int, error) {
	var pids []int
	lines := strings.Split(lsnsOutput, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[2] != "" {
			pidStr := fields[3]
			pid, err := strconv.Atoi(pidStr)
			if err == nil {
				pids = append(pids, pid)
			}
		}
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("no valid PIDs found in lsns output")
	}
	return pids, nil
}

func runLsnsAndGetPIDs() ([]int, error) {
	cmd := exec.Command("lsns", "-t", "net")
	outputBytes, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run lsns command: %w", err)
	}

	output := string(outputBytes)
	return extractPIDsFromLsnsOutput(output)
}

func getNamespacePath(pid int) (string, error) {
	netNsPath := filepath.Join("/proc", strconv.Itoa(pid), "ns", "net")
	return netNsPath, nil
}

func setTotalBw(etherName string, totalBw int) error {
	// totalBw 1000Mbps 1048576000bit
	// tc qdisc add dev <interface_name> root tbf rate 100mbit burst 10mb latency 50ms
	cmd := exec.Command("tc", "qdisc", "replace", "dev", etherName, "root", "tbf", "rate", strconv.Itoa(totalBw)+"mbit", "burst", "2mb", "latency", "50ms")
	// sudo tc qdisc del dev enp0s8 root

	// 打印命令行以供调试
	fmt.Println(cmd.String())

	// 执行命令
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	fmt.Printf("Set Totalbw %d Mbps on %s\n", totalBw, etherName)
	return nil
}

const Logfile string = "./bwm-cli.log"

func setLog(levelStr string) (func(), error) {
	file, err := os.OpenFile(Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("open file %s, err:%v", Logfile, err)
	}

	log.SetOutput(file)
	if level, err := log.ParseLevel(levelStr); err != nil {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(level)
	}
	return func() {
		file.Close()
	}, nil
}

func main() {
	// Load the compiled eBPF ELF and load it into the kernel.
	lnFlag := flag.Bool("ln", false, "list namespace and inner vethname")
	eFlag := flag.String("e", "", "Load eBPF program")
	dFlag := flag.String("d", "", "Unload eBPF program")
	sFlag := flag.String("s", "", "Check if eBPF program is mounted")
	sqFlag := flag.String("sq", "", "Set totalbw to enp0s8, e.g. 100")
	aFlag := flag.String("a", "", "load config from json and run a daemon, input totalbw, e.g. 100")

	flag.Parse()

	closeLogFile, err := setLog("debug") // debug  info  error  fatal
	if err != nil {
		fmt.Printf("set cli logfile err: %v\n", err)
		return
	}
	defer closeLogFile()

	// 执行对应操作
	if *lnFlag == true {
		pids, err := runLsnsAndGetPIDs()
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			fmt.Printf("Extracted PIDs: %d\n", pids)
		}
	} else if *eFlag != "" {
		if *eFlag == "all" {
			// 对所有namespace，所有网卡操作？
		} else {
			etherName := "eth0"
			pid, err := strconv.Atoi(*eFlag)
			if err != nil {
				fmt.Println("Error pid:", *eFlag, err)
				return
			}

			if _, err := os.Stat(bpf.EdtBpfProgPath); os.IsNotExist(err) {
				fmt.Println(bpf.EdtBpfProgPath, "不存在, 复制到", "/usr/share/bwm")
				cmd := exec.Command("mkdir", "/usr/share/bwm")
				err = cmd.Run()
				cmd = exec.Command("cp", "../tcedt_bpfel.o", bpf.EdtBpfProgPath)
				err = cmd.Run()
			}

			npath, err := getNamespacePath(pid)
			if err != nil {
				fmt.Printf("error get namespace path on %d : %v\n", pid, err)
				return
			}
			err = bpf.EnableDevQos(etherName, npath, bpf.EgressBpfSection)
			if err != nil {
				fmt.Printf("error enable EdtTc on %s : %v\n", npath, err)
				return
			}
			fmt.Println("EnableDevQos Success!")

			// sudo nsenter -n -t 10651 tc filter show dev eth0 egress
		}
	} else if *dFlag != "" {
		if *dFlag == "all" {
			// 对所有namespace，所有网卡操作？
		} else {
			etherName := "eth0"
			pid, err := strconv.Atoi(*dFlag)
			if err != nil {
				fmt.Println("Error pid:", *eFlag, err)
				return
			}
			npath, err := getNamespacePath(pid)
			if err != nil {
				fmt.Printf("error get namespace path on %d : %v\n", pid, err)
				return
			}
			err = bpf.DisableDevQos(etherName, npath, bpf.EgressBpfSection)
			if err != nil {
				fmt.Printf("error disable EdtTc on %s : %v\n", npath, err)
				return
			}
			fmt.Println("DisableDevQos Success!")
		}
	} else if *sFlag != "" {
		if *sFlag == "all" {
			// 对所有namespace，所有网卡操作？
		} else {
			etherName := "eth0"
			pid, err := strconv.Atoi(*sFlag)
			if err != nil {
				fmt.Println("Error pid:", *eFlag, err)
				return
			}
			npath, err := getNamespacePath(pid)
			if err != nil {
				fmt.Printf("error get namespace path on %d : %v\n", pid, err)
				return
			}
			loaded, err := bpf.IsDevQosEnabled(etherName, npath)
			if err != nil {
				fmt.Printf("error check EdtTc on %s : %v\n", npath, err)
				return
			}
			fmt.Println(loaded)
		}
	} else if *aFlag != "" {
		// 100_run  : set and run daemon proc
		// 100  : only set ebpf map from config json
		splitWords := strings.Split(*aFlag, "_")
		fmt.Printf("%v\n", splitWords)
		var daemonProcess *bpf.DaemonProc

		fmt.Println("Load config to ebpf map and run daemonProc")

		edtBpf, err := bpf.NewTcbpf()
		if err != nil {
			fmt.Printf("init edtBpf failed: %v\n", err)
			return
		}

		totalbw, err := strconv.Atoi(splitWords[0]) // 100 1000 Mbps
		if err != nil {
			fmt.Println("Error totalbw:", splitWords[0])
			fmt.Println("Error:", err)
			return
		}

		totalBandWidth := uint64(totalbw * 1024 * 1024 / 8)
		daemonProcess = bpf.NewDaemonProc(totalBandWidth, totalBandWidth, 15, edtBpf) // speed单位？ Mb/s | ebpf程序的速度>是byte -> 需要转换

		configPath := "./config.json"
		containers, err := ReadConfig(configPath)
		if err != nil {
			fmt.Printf("readconfig from %s failed: %v\n", configPath, err)
			return
		}

		for _, con := range containers {
			// 加载container的qos配置到cfg map
			// 拼接container的classid路径
			classidPathPrefix := "/sys/fs/cgroup/net_cls/docker"
			classidFile := "net_cls.classid"
			classidPath := path.Join(classidPathPrefix, string(con.UID), classidFile)
			fmt.Printf("Pod classidPath: %s\n", classidPath)

			classid := bpf.GenerateClassId(uint32(con.SendPriority), uint16(con.Id))
			fmt.Printf("generate classid: %d\n", classid)
			if err = bpf.SetEgressClassid(classidPath, classid); err != nil {
				err = fmt.Errorf("SetCgroupV1Classid failed, err: %v", err)
				fmt.Printf("%v", err)
				return
			}
			fmt.Printf("SetCgroupV1Classid Success!\n")

			egressConfig := common.QosConfig{
				BandWidthRequestM: uint64(con.SendBandWidthRequestM),
				BandWidthLimitM:   uint64(con.SendBandWidthRequestM),
				Priority:          uint32(con.SendPriority),
			}

			ingressConfig := common.QosConfig{
				BandWidthRequestM: uint64(con.SendBandWidthRequestM),
				BandWidthLimitM:   uint64(con.SendBandWidthRequestM),
				Priority:          uint32(con.SendPriority),
			}
			daemonProcess.AddEgressConfig(uint32(con.Id), egressConfig)
			daemonProcess.AddIngressConfig(uint32(con.Id), ingressConfig)
		}
		if len(splitWords) == 2 && splitWords[1] == "run" {
			daemonProcess.Run(0)
		}
	} else if *sqFlag != "" {
		totalbw, err := strconv.Atoi(*sqFlag) // 100 1000 Mbps
		if err != nil {
			fmt.Println("Error totalbw:", *aFlag)
			fmt.Println("Error:", err)
			return
		}

		etherName := "enp7s0"
		err = setTotalBw(etherName, totalbw)
		if err != nil {
			fmt.Printf("Error Set totalbw to %s\n", etherName)
			fmt.Println("Error:", err)
			return
		}
	}
}
