# oncn-bwm

## 介绍

本特性通过区分在线、离线业务从而既能保证在线业务带宽的需求，还能保证充分的利用网络带宽资源。
具体提供了下列功能：

### 支持设置Pod网络优先级
1.  以执行bwmcli命令的方式设置某个cgroup的网络优先级，执行bwmcli命令时需要指定的参数包括：cgrp_path、prio
2.  优先级默认值为0，0标识为在线业务，-1标识为离线业务。

###  支持设置离线业务网络带宽限制
1.  Pod网络带宽限制对所有离线业务生效，所有离线业务的总带宽不能超过设置的网络带宽限制，在线业务没有网络带宽限制。
2.  以执行bwmcli命令的方式设置一个主机/虚拟机的离线业务网络带宽限制，执行bwmcli命令时需要指定的参数包括：允许使用的：最低带宽(KB/MB/GB)，最高带宽(KB/MB/GB)
3.  网络带宽限制特性与水线特性共同完成离线业务带宽限制，当在线业务带宽低于设置的水线时：离线业务允许使用设置的最高带宽，当在线业务带宽高于设置的水线时，离线业务允许使用设置的最低带宽。

### 支持设置在线业务水线
1.  以执行bwmcli命令的方式设置一个主机/虚拟机的在线业务的水线，执行bwmcli命令时需要指定的参数包括：水线值(KB/MB/GB)
2.  当一个主机上所有在线业务的总带宽高于水线时，会限制离线业务可以使用的带宽，反之当一个主机上所有在线业务的总带宽低于水线时，会提高离线业务可以使用的带宽。
3.  判断在线业务的总带宽是否超过/低于设置的水线的时机：每10ms判断一次，根据每个10ms内统计的在线带宽是否高于水线来决定对离线业务采用的带宽限制。

###  支持使能/除能Pod网络Qos功能
1.  以执行bwmcli命令的方式来使能/除能一个网卡的Qos功能，执行bwmcli命令时需要指定的参数包括：网卡名，不指定网卡名则默认操作主机上的所有网卡。
2.  一个主机上的所有使能Qos功能的网卡在实现内部被当成一个整体看待，也就是共享设置的水线和网络带宽限制。

## 软件架构
```
oncn-bwm
│  bwmcli.c # bwmcli命令行工具
│  bwmcli.h
│  CMakeLists.txt
│  LICENSE
│  README.md
│
├─bpf # 两个ebpf程序文件实现带宽管理逻辑
│
├─ko # 提供内核proc文件接口
│
└─tools # 在离线带宽检测工具，基于bpftrace
```

## 安装教程

1.  yum install oncn-bwm

## 使用说明

### 命令行接口说明
**接口1**

说明
```
bwmcli -e/-d ethx 使能/除能某个网卡的Qos功能
bwmcli -e/-d 使能/除能所有网卡的Qos功能
```
示例
```
# bwmcli -e eth0 -e eth1
enable eth0 success
enable eth1 success

# bwmcli -d eth0 -d eth1
disable eth0 success
disable eth1 success
```

**接口2**

说明
```
bwmcli -s path <prio> 设置某个cgroup的优先级
bwmcli -p path 查询某个cgroup的优先级
```
示例
```
# bwmcli -s /sys/fs/cgroup/net_cls/test_online 0
set prio success

# bwmcli -p /sys/fs/cgroup/net_cls/test_online
prio is 0
```

**接口3**	

说明
```
bwmcli -s bandwidth <low,high> 设置离线带宽
bwmcli -p bandwidth 查询离线带宽
```
示例
```
# bwmcli -s bandwidth 30mb,100mb
set bandwidth success

# bwmcli -p bandwidth
bandwidth is 31457280(B),104857600(B)
```

**接口4**	

说明
```
bwmcli -s waterline <val> 设置在线水线
bwmcli -p waterline 查询在线水线
```
示例	
```
# bwmcli -s waterline 20mb
set waterline success

# bwmcli -p waterline
waterline is 20971520 (B)
```

**接口5**	

说明
```
bwmcli -p stats 打印内部统计信息
```
示例
```
# bwmcli -p stats
rate: 1073741824
online_pkts: 79752
offline_pkts: 69730
online rate past: 0
offline rate past: 916194823
```

**接口6**	

说明
```
bwmcli -p devs 描述系统上所有网卡的使能状态
```
示例	
```
# bwmcli -p devs
lo              : disabled
enp2s2          : disabled
```

### proc文件接口说明

**接口1**

说明
```
/proc/qos/net_qos_enable:使能网络qos功能
```

示例
```
# 使能对应namespace中网络设备的qos功能
echo $nspid > /proc/qos/net_qos_enable
```

**接口2**

说明
```
/proc/qos/net_qos_disable:除能网络qos功能
```

示例
```
# 除能对应namespace中网络设备的qos功能
echo $nspid > /proc/qos/net_qos_disable
```

**接口3**

说明
```
/proc/qos/net_qos_bandwidth:设置/查询离线业务带宽上下限
```

示例
```
# 设置离线业务带宽上下限
echo "$low,$high" > /proc/qos/net_qos_bandwidth
# 查询离线业务带宽上下限
cat /proc/qos/net_qos_bandwidth
```

**接口4**

说明
```
/proc/qos/net_qos_waterline:设置/查询在线业务带宽水线
```

示例
```
# 设置在线业务带宽水线
echo "$val" > /proc/qos/net_qos_waterline
# 查询在线业务带宽水线
cat /proc/qos/net_qos_waterline
```

**接口5、6**

说明
```
接口5、6为组合接口
/proc/qos/net_qos_devs:将需要查询的容器对应的nspid输入该接口，该容器网络设备的qos状态将被记录在/proc/qos/net_qos_devstatus中
/proc/qos/net_qos_devstatus:用于输出/proc/qos/net_qos_devs中对应容器网络设备的qos状态
```

示例
```
# 输入对应容器环境的nspid，对应容器中网络设备的qos使能状态记录在/proc/qos/net_qos_devstatus中
echo $nspid > /proc/qos/net_qos_devs
cat /proc/qos/net_qos_devstatus
```

**接口7**

说明
```
/proc/qos/net_qos_stats:查询整个host环境上在离线业务的统计信息
```

示例
```
# 查询在离线业务的统计信息
cat /proc/qos/net_qos_stats
```

## 使用案例

### 基本使用案例

```
bwmcli -p devs 查询系统当前网卡使能状态
bwmcli -s /sys/fs/cgroup/net_cls/online 0
bwmcli -s /sys/fs/cgroup/net_cls/offline -1
bwmcli -e eth0 使能eth0的网卡 Qos功能
bwmcli -s bandwidth 20mb,1gb 配置离线业务带宽
bwmcli -s waterline 30mb 配置在线业务的水线
```

### cni插件使用案例

这里以calico网络插件为例，插件配置路径：/etc/cni/net.d/10-calico.conflist
将自定义的插件添加到plugins列表中（一般加在最后，确保网卡此时已创建完成），指定插件程序名称，并在插件程序存放路径（/opt/cni/bin/）下存放对应的可执行程序，这里可执行程序为shell脚本，命名为bwm-cni
```json{30-32}
{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "log_level": "info",
      "datastore_type": "kubernetes",
      "nodename": "node1",
      "mtu": 1440,
      "ipam": {
          "type": "calico-ipam"
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "/etc/cni/net.d/calico-kubeconfig"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    },
    {
      "type": "bandwidth",
      "capabilities": {"bandwidth": true}
    },
    {
      "type": "bwm-cni" #插件可执行程序名称为bwm-cni
    }
  ]
}
```

bwm-cni可执行脚本示例
```shell
#!/bin/bash -e

case $CNI_COMMAND in
ADD)

#使能网卡的qos功能
nsenter --net=$CNI_NETNS bwmcli -e $CNI_IFNAME >&2
echo "{}"

;;

DEL)

echo "{}"
;;

VERSION)
echo '{
  "cniVersion": "0.3.1",
  "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ]
}'
;;

*)
  echo "Unknown cni command: $CNI_COMMAND"
  exit 1
;;

esac
```

## 约束限制

1. 命令行接口和proc文件接口在设置离线业务带宽和在线业务水线上存在不同步的问题，通过proc文件接口设置的结果可以用命令行接口查询到，而通过命令行设置的结果不可以通过proc文件接口查询到。
2. 实际使用过程中，带宽限速有可能造成协议栈内存积压，此时依赖传输层协议自行反压，对于udp等无反压机制的协议场景，可能出现丢包、ENOBUFS、限速有偏差等问题。

## 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request


## 特技

1.  使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2.  Gitee 官方博客 [blog.gitee.com](https://blog.gitee.com)
3.  你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解 Gitee 上的优秀开源项目
4.  [GVP](https://gitee.com/gvp) 全称是 Gitee 最有价值开源项目，是综合评定出的优秀开源项目
5.  Gitee 官方提供的使用手册 [https://gitee.com/help](https://gitee.com/help)
6.  Gitee 封面人物是一档用来展示 Gitee 会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
