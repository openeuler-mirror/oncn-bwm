package tc

import (
	"fmt"
	bpf "oncn-bwm/pkg/bpfgo"
	"oncn-bwm/pkg/github.com/vishvananda/netlink"
	"runtime"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var Custom string

const FilterPriority = 2

func CreateIfbDev(ifbName string) error {
	link, err := netlink.LinkByName(ifbName)
	if err != nil {
		// 创建一个IFB设备
		var newLink netlink.Link
		if Custom == "DAHUA" {
			newLink = &netlink.DhcIfb{
				LinkAttrs: netlink.LinkAttrs{
					MTU:         1500,
					TxQLen:      1000,
					Name:        ifbName,
					NumTxQueues: runtime.NumCPU(),
				},
			}
		} else {
			newLink = &netlink.Ifb{
				LinkAttrs: netlink.LinkAttrs{
					MTU:         1500,
					TxQLen:      1000,
					Name:        ifbName,
					NumTxQueues: runtime.NumCPU(),
				},
			}
		}

		// 添加IFB设备
		if err := netlink.LinkAdd(newLink); err != nil {
			return errors.Errorf("add ifb devvice failed, err: %v\n", err)
		}
		link = newLink
	}

	// 启动IFB设备
	if err := netlink.LinkSetUp(link); err != nil {
		return errors.Errorf("startup ifb device failed, err: %v\n", err)
	}

	log.Infof("create ifb device %s success\n", ifbName)

	return nil
}

func DestroyIfbDev(ifbName string) error {
	// 获取ifb0网卡的Link对象
	ifb, err := netlink.LinkByName(ifbName)
	if err != nil {
		fmt.Errorf("get interface: %s failed, err: %v\n", ifbName, err)
		return err
	}

	// 删除ifb0网卡
	err = netlink.LinkDel(ifb)
	if err != nil {
		fmt.Errorf("del interface: %s failed, err: %s\n", ifbName, err)
		return err
	}

	fmt.Printf("del ifb device %s success\n", ifbName)
	return nil
}

func NicIngressFilterToIfb(hostNicName string, ifbName string) error {
	// LinkByName 获取网络接口的引用
	link, err := netlink.LinkByName(hostNicName)
	if err != nil {
		return errors.Errorf("get interface: %s failed, err: %v\n", hostNicName, err)
	}
	// 检查是否已经有dhcmatchall filter
	filterList, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return errors.Errorf("list %s filter failed, err: %v", hostNicName, err)
	}
	filterType := "matchall"
	for _, tmpFilter := range filterList {
		if Custom == "DAHUA" {
			filterType = "dhcmatchall"
		}
		if tmpFilter.Type() == filterType {
			if tmpFilter.Attrs().Priority == FilterPriority {
				return nil
			} else {
				if err := netlink.FilterDel(tmpFilter); err != nil {
					return errors.Errorf("del %s filter %v failed, err: %v", hostNicName, tmpFilter, err)
				}
			}
		}
	}

	ifbLink, err := netlink.LinkByName(ifbName)
	if err != nil {
		return errors.Errorf("get interface: %s failed, err: %v\n", ifbName, err)
	}
	// 创建 Mirred Action
	mirredAction := netlink.NewMirredAction(ifbLink.Attrs().Index)
	mirredAction.MirredAction = netlink.TCA_EGRESS_REDIR

	// 构建 MatchAll 过滤器
	var filter netlink.Filter
	if Custom == "DAHUA" {
		filter = &netlink.DhcMatchAll{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS, // 对应 ffff: 使用 HANDLE_MIN_INGRESS
				Priority:  FilterPriority,
				Protocol:  unix.ETH_P_ALL,
			},
			Actions: []netlink.Action{mirredAction}, // 将 Mirred Action 添加到动作列表
		}
	} else {
		filter = &netlink.MatchAll{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS, // 对应 ffff: 使用 HANDLE_MIN_INGRESS
				Priority:  FilterPriority,
				Protocol:  unix.ETH_P_ALL,
			},
			Actions: []netlink.Action{mirredAction}, // 将 Mirred Action 添加到动作列表
		}
	}

	// 添加过滤器
	if err := netlink.FilterReplace(filter); err != nil {
		return errors.Errorf("add filter failed, err: %v\n", err)
	}

	log.Infof("add redirect filter success\n")
	return nil
}

func DisableNicIngressFilterToIfb(hostNicName string) error {
	// LinkByName 获取网络接口的引用
	link, err := netlink.LinkByName(hostNicName)
	if err != nil {
		return errors.Errorf("get interface: %s failed, err: %v\n", hostNicName, err)
	}
	// 检查是否已经有dhcmatchall filter
	filterList, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return errors.Errorf("list %s filter failed, err: %v", hostNicName, err)
	}

	for _, tmpFilter := range filterList {
		if tmpFilter.Type() == "dhcmatchall" {
			if err := netlink.FilterDel(tmpFilter); err != nil {
				return errors.Errorf("del %s filter %v failed, err: %v", hostNicName, tmpFilter, err)
			}
		}
	}
	return nil
}

func EnableIngressQos(hostNicName string, ifbName string) error {
	err := CreateIfbDev(ifbName)
	if err != nil {
		err = errors.Wrapf(err, "create ifb dev %s failed, err: %v", ifbName, err)
		return err
	}

	err = NicIngressFilterToIfb(hostNicName, ifbName)
	if err != nil {
		err = errors.Wrapf(err, "nicIngressFilterToIfb failed, err: %v", err)
		return err
	}

	err = bpf.EnableDevQos(ifbName, "", bpf.IngressBpfSection)
	if err != nil {
		err = errors.Wrapf(err, "enable dev %s Qos failed, err: %v", ifbName, err)
		return err
	}

	return nil
}

func DisableIngressQos(hostNicName string, ifbName string) error {
	if err := bpf.DisableDevQos(ifbName, "", bpf.IngressBpfSection); err != nil {
		log.Errorf("disable %s dev Qos failed, err: %v", ifbName, err)
	}

	if err := DisableNicIngressFilterToIfb(hostNicName); err != nil {
		log.Errorf("disable %s matchall filter failed, err: %v", hostNicName, err)
		return err
	}

	if err := DestroyIfbDev(ifbName); err != nil {
		log.Errorf("destroy ifb dev %s failed, err: %v", ifbName, err)
		return err
	}

	return nil
}
