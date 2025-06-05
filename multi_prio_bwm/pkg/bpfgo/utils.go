package bpf

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"oncn-bwm/pkg/github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	netns "github.com/containernetworking/plugins/pkg/ns"
	log "github.com/sirupsen/logrus"
)

var (
	bpfCache = make(map[string]*cachedProgram)
)

const (
	Attach = 0
	Detach = 1
)

type cachedProgram struct {
	prog *ebpf.Program
	coll *ebpf.Collection
}

func getFileName(path string) (string, error) {
	fileName := filepath.Base(path)
	return fileName, nil
}

// 低16位存放优先级，高16位存放Pod ID（生成的）
func GenerateClassId(priority uint32, podId uint16) uint32 {
	classId := (uint32(podId) << 16) | priority
	return classId
}

func SetEgressClassid(classidPath string, classid uint32) error {
	file, err := os.OpenFile(classidPath, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		fmt.Printf("failed to open classid file path: %v, %v\n", classidPath, err)
		return err
	}
	defer file.Close()

	str := strconv.FormatUint(uint64(classid), 10)
	if err := ExecuteWithRedirect("echo", []string{str}, file); err != nil {
		fmt.Printf("failed to exec cmd with redirect: %v", err)
		return err
	}

	return nil
}

func executeCore(cmd string, args []string, stdout, stderr io.Writer) error {
	var err error

	cmdPath, err := exec.LookPath(cmd)
	if err != nil {
		fmt.Println("command failed to get path")
		return err
	}

	args = append([]string{cmd}, args...)
	if stdout == nil {
		stdout = &bytes.Buffer{}
	}

	command := exec.Cmd{
		Path:   cmdPath,
		Args:   args,
		Stdout: stdout,
		Stderr: stderr,
	}

	command.Run()
	return nil
}

func ExecuteWithRedirect(cmd string, args []string, stdout io.Writer) error {
	if stdout == nil {
		return fmt.Errorf("stdout can not be null in output redirect mode")
	}
	stderr := &bytes.Buffer{}
	if err := executeCore(cmd, args, stdout, stderr); err != nil {
		return err
	}
	if len(stderr.String()) != 0 {
		return fmt.Errorf("command error output: %s", stderr.String())
	}
	return nil
}

type tcCommand struct {
	cmdStr    string
	verifyRet bool
}

func checkQosEnabled(cmd string) error {
	output, err := exec.Command("bash", "-c", cmd).CombinedOutput()

	if err != nil {
		// 如果执行出错，说明没有挂载对应的 eBPF 程序
		return fmt.Errorf("without ebpf loaded")
	}

	if len(output) == 0 {
		// 如果命令执行成功且没有输出，说明挂载了相应的 eBPF 程序
		return nil
	}

	// 如果有输出，说明没有挂载对应的 eBPF 程序
	return fmt.Errorf("without ebpf loaded")
}

func IsDevQosEnabled(interfaceName string, namespace string) (bool, error) {
	cmd := fmt.Sprintf("tc filter show dev %s egress | grep -E %s >/dev/null 2>&1", interfaceName, "'bpfel.o|bpfeb.o'") // 小端问题
	execFunc := func(netns.NetNS) error {
		log.Debugf("Running check cmd in namespace: %s", namespace)
		return checkQosEnabled(cmd)
	}

	if namespace != "" {
		err := netns.WithNetNSPath(namespace, execFunc)
		if err != nil {
			return false, fmt.Errorf("%v", err)
		}
	} else {
		err := checkQosEnabled(cmd)
		if err != nil {
			log.Errorf("doCmdExecute failed: %v", err)
			return false, fmt.Errorf("%v", err)
		}
	}

	return true, nil
}

func EnableDevQos(interfaceName string, namespace string, section string) error {
	configFunc := func(ns netns.NetNS) error {
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			return errors.Wrapf(err, "failed to get network interface: %s", interfaceName)
		}

		err = setupRootQdisc(link)
		if err != nil {
			return err
		}

		err = setupClsactQdisc(link)
		if err != nil {
			return err
		}
		var prog *ebpf.Program
		prog, err = loadBpfProgram(section)
		if err != nil {
			return err
		}

		err = setupBpfFilter(prog, link, section, Attach)
		if err != nil {
			return err
		}

		return nil
	}
	if namespace != "" {
		return netns.WithNetNSPath(namespace, configFunc)
	}
	return configFunc(nil)
}

func setupRootQdisc(link netlink.Link) error {
	mq := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: "mq",
	}

	if err := netlink.QdiscReplace(mq); err != nil {
		return errors.Wrap(err, "mq qdisc replace failed")
	}
	return nil
}

func setupClsactQdisc(link netlink.Link) error {
	clsActAttrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	clsActQdisc := &netlink.GenericQdisc{
		QdiscAttrs: clsActAttrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscReplace(clsActQdisc); err != nil {
		return fmt.Errorf("while replace clsact qdisc: %v", err)
	}
	return nil
}

func loadBpfProgram(section string) (*ebpf.Program, error) {
	coll, err := ebpf.LoadCollection(EdtBpfProgPath)
	if err != nil {
		return nil, fmt.Errorf("load ebpf prog err: %w", err)
	}

	prog := coll.Programs[section]
	if prog == nil {
		return nil, fmt.Errorf("can not find section %q", section)
	}

	bpfCache[section] = &cachedProgram{
		prog: prog,
		coll: coll,
	}
	return prog, nil
}

func setupBpfFilter(prog *ebpf.Program, link netlink.Link, section string, mode int) error {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  2,
		},
		Fd:           prog.FD(),
		Name:         section,
		DirectAction: true,
	}

	if mode == Attach {
		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("failed to replace filter for interface %v: %v", link.Attrs().Name, err)
		}
	} else if mode == Detach {
		if err := netlink.FilterDel(filter); err != nil {
			return fmt.Errorf("failed to delete filter for interface %v: %v", link.Attrs().Name, err)
		}
		cleanupCachedProgram(section)
	} else {
		return fmt.Errorf("invalid mode in ManageTCProgramByFd")
	}
	return nil
}

func DisableDevQos(interfaceName string, namespace string, section string) error {
	mounted, err := IsDevQosEnabled(interfaceName, namespace)
	if err != nil { // 检查挂载出错，也按出错处理
		log.Errorf("IsDevQosEnabled run failed, err: %v", err)
		return err
	}
	if !mounted { // 之前没有挂载，直接跳过
		log.Infof("dev: %s qos already disable", interfaceName)
		return nil
	}
	link, _ := netlink.LinkByName(interfaceName)

	return setupBpfFilter(bpfCache[section].prog, link, section, Detach)
}

func cleanupCachedProgram(section string) {
	if cp, exists := bpfCache[section]; exists {
		cp.coll.Close()
		delete(bpfCache, section)
	}
}
