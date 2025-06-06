package lib

import (
	"fmt"
	"github.com/containernetworking/plugins/pkg/ns"
	"oncn-bwm/pkg/github.com/vishvananda/netlink"
)

type VethPeer struct {
	VethHostMac  string
	VethHostName string //宿主机侧网卡对
	VethLXCMac   string
	VethLXCName  string //容器内侧网卡对
	VethIP       string
	VethIPv6     string
	VethHostIdx  int
}

func GetVethPeerInfo(nspath string) (*VethPeer, error) {
	var (
		hostMac, vethHostName, vethLXCMac, vethLXCName, vethIP, vethIPv6 string
		vethHostIdx, peerIndex                                           int
		peer                                                             netlink.Link
	)

	netNs, err := ns.GetNS(nspath)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %s", nspath, err)
		return nil, err
	}
	defer netNs.Close()

	if err = netNs.Do(func(_ ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return nil
		}
		linkFound := false
		for _, link := range links {
			if link.Type() != "veth" {
				continue
			}
			vethLXCMac = link.Attrs().HardwareAddr.String()
			vethLXCName = link.Attrs().Name
			veth, ok := link.(*netlink.Veth)
			if !ok {
				return fmt.Errorf("link %s is not a veth interface", vethHostName)
			}
			peerIndex, err = netlink.VethPeerIndex(veth)
			if err != nil {
				return fmt.Errorf("unable to retrieve index of veth peer %s: %s", vethHostName, err)
			}

			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err == nil && len(addrs) > 0 {
				vethIP = addrs[0].IPNet.IP.String()
			}

			addrsv6, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err == nil && len(addrsv6) > 0 {
				vethIPv6 = addrsv6[0].IPNet.IP.String()
			}

			linkFound = true
			break
		}
		if !linkFound {
			return fmt.Errorf("no link found inside container")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	peer, err = netlink.LinkByIndex(peerIndex)
	if err != nil {
		err = fmt.Errorf("unable to lookup link %d: %s", peerIndex, err)
		return nil, err
	}

	hostMac = peer.Attrs().HardwareAddr.String()
	vethHostName = peer.Attrs().Name
	vethHostIdx = peer.Attrs().Index

	switch {
	case vethHostName == "":
		err = fmt.Errorf("unable to determine name of veth pair on the host side")
		return nil, err
	case vethLXCMac == "":
		err = fmt.Errorf("unable to determine MAC address of veth pair on the container side")
		return nil, err
	case vethIP == "" && vethIPv6 == "":
		err = fmt.Errorf("unable to determine IP address of the container")
		return nil, err
	case vethHostIdx == 0:
		err = fmt.Errorf("unable to determine index interface of veth pair on the host side")
		return nil, err
	}
	return &VethPeer{
		VethHostMac:  hostMac,
		VethHostName: vethHostName,
		VethLXCMac:   vethLXCMac,
		VethLXCName:  vethLXCName,
		VethIP:       vethIP,
		VethIPv6:     vethIPv6,
		VethHostIdx:  vethHostIdx,
	}, nil
}
