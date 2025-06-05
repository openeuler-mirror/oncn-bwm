package common

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"oncn-bwm/pkg/github.com/vishvananda/netlink"
)

// 找默认路由
func lookupDefaultRoute(family int) (netlink.Route, error) {
	linkIndex := 0

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		return netlink.Route{}, fmt.Errorf("unable to list direct routes: %s", err)
	}

	if len(routes) == 0 {
		return netlink.Route{}, fmt.Errorf("default route not found for family %d", family)
	}

	for _, route := range routes {
		if linkIndex != 0 && linkIndex != route.LinkIndex {
			fmt.Printf("[Warning]:found default routes with different netdev index: %v vs %v, use the first default route\n",
				linkIndex, route.LinkIndex)
			break
		}
		linkIndex = route.LinkIndex
	}

	return routes[0], nil
}

// 通过默认路由找到master网卡
func GetMasterIntf() (string, error) {
	linkIndex := 0
	route, err := lookupDefaultRoute(netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("lookup default route failed, err: %v", err)
	}
	linkIndex = route.LinkIndex
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return "", fmt.Errorf("get link by index failed, err: %v", err)
	}

	return link.Attrs().Name, nil
}

// 获取网卡带宽
func GetNetworkInterfaceSpeed(interfaceName string) (uint64, error) {
	// 读取网卡速度文件
	speedFilePath := fmt.Sprintf("/sys/class/net/%s/speed", interfaceName)
	content, err := ioutil.ReadFile(speedFilePath)
	if err != nil {
		return 0, err
	}

	// 转换为字符串并去除可能的空白字符
	speedStr := strings.TrimSpace(string(content))

	// 将字符串转换为 uint64
	speed, err := strconv.ParseUint(speedStr, 10, 64)
	if err != nil {
		return 0, err
	}

	return speed, nil
}
