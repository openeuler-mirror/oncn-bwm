# oncn-bwm

## 介绍

本特性通过区分在线、离线业务从而既能保证在线业务带宽的需求，还能保证充分的利用网络带宽资源。
具体提供了下列功能：

### 支持设置Pod网络优先级
##### 出向
1.  以执行bwmcli命令的方式设置某个cgroup的网络优先级，执行bwmcli命令时需要指定的参数包括：cgrp_path、prio
2.  优先级默认值为0，0标识为在线业务，-1标识为离线业务。
##### 入向
1.  以执行bwmcli命令的方式设置某个目标ip数据包的网络优先级，执行bwmcli命令时需要指定的参数包括：ip
2.  未设置的ip默认被认为是在线业务，被设置ip被认为是离线业务。

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
│  bwmcli.c          # bwmcli命令行工具
│  bwmcli.h          # 头文件及常量定义
│  CMakeLists.txt
│  LICENSE
│  README.md
│
├─bpf                # eBPF程序实现带宽管理逻辑
│  ├─bwm_prio_kern.c # cgroup优先级设置程序，通过cgroup_skb/egress钩子设置数据包优先级
│  ├─bwm_tc.c        # 出向带宽管理TC程序，通过cgroup classid区分在线/离线流量
│  ├─bwm_tc_i.c      # 入向带宽管理TC程序，通过解析目标IP区分在线/离线流量
│  ├─bwm_tc.h        # 共享数据结构定义（带宽配置、限流状态、统计信息）
│  └─bwm_tc_common.h # 内联辅助函数（在线/离线流量处理、速率调整、限流初始化）
│
└─tools              # 在离线带宽检测工具，基于bpftrace
```

## 安装教程

1.  cmake .
2.  make
3.  mkdir -p /usr/share/bwmcli
4.  install -Dpm 0500 bpf/CMakeFiles/bwm_prio_kern.dir/bwm_prio_kern.c.o /usr/share/bwmcli/bwm_prio_kern.o
5.  install -Dpm 0500 bpf/CMakeFiles/bwm_tc.dir/bwm_tc.c.o /usr/share/bwmcli/bwm_tc.o
6.  install -Dpm 0500 bpf/CMakeFiles/bwm_tc_i.dir/bwm_tc_i.c.o /usr/share/bwmcli/bwm_tc_i.o
7.  install -Dpm 0500 bwmcli /usr/bin
8.  install -Dpm 0500 tools/bwm_monitor.bt /usr/bin
9.  install -Dpm 0500 tools/bwm_monitor_ingress.bt /usr/bin

## 使用说明

### 接口说明

**接口1：网卡QoS使能/除能**
```
bwmcli -e/-d ethx    # 使能/除能某个网卡的出向QoS功能
bwmcli -e/-d         # 使能/除能所有网卡的出向QoS功能
bwmcli -E/-D ethx    # 使能/除能某个网卡的入向QoS功能
bwmcli -E/-D         # 使能/除能所有网卡的入向QoS功能
bwmcli -v            # 显示版本号
```
示例
```bash
# bwmcli -e eth0 -e eth1
enable eth0 success
enable eth1 success

# bwmcli -d eth0 -d eth1
disable eth0 success
disable eth1 success

# bwmcli -v
version: 1.0
```

**接口2：cgroup优先级设置（出向）**
```
bwmcli -s path <prio>  # 设置某个cgroup的优先级（支持cgroup v1/v2）
bwmcli -p path         # 查询某个cgroup的优先级
```
- 优先级0表示在线业务，-1表示离线业务
- cgroup v1路径示例：`/sys/fs/cgroup/net_cls/xxx`
- cgroup v2路径示例：`/sys/fs/cgroup/xxx`
示例
```bash
# bwmcli -s /sys/fs/cgroup/net_cls/test_online 0
set prio success

# bwmcli -p /sys/fs/cgroup/net_cls/test_online
prio is 0
```

**接口3：IP优先级设置（入向）**
```
bwmcli -A <ip>  # 标识对应IP入向流为离线流量
bwmcli -R <ip>  # 标识对应IP入向流为在线流量
```
- 未配置的IP默认为在线业务
示例
```bash
# bwmcli -A 172.17.0.2
AddIp 172.17.0.2 success
# bwmcli -R 172.17.0.2
RemoveIp 172.17.0.2 success
```

**接口4：带宽限制设置**
```
bwmcli -s bandwidth <low,high>  # 设置出向离线带宽
bwmcli -p bandwidth              # 查询出向离线带宽
bwmcli -S bandwidth <low,high>  # 设置入向离线带宽
bwmcli -P bandwidth              # 查询入向离线带宽
```
- 带宽范围：1MB ~ 9999GB
- low：离线业务低带宽（水线触发时使用）
- high：离线业务高带宽（水线未触发时使用）
示例
```bash
# bwmcli -s bandwidth 30mb,100mb
set bandwidth success

# bwmcli -p bandwidth
bandwidth is 31457280(B),104857600(B)
```

**接口5：水线设置**
```
bwmcli -s waterline <val>  # 设置出向在线业务水线
bwmcli -p waterline        # 查询出向在线业务水线
bwmcli -S waterline <val>  # 设置入向在线业务水线
bwmcli -P waterline        # 查询入向在线业务水线
```
- 水线范围：20MB ~ 9999GB
- 在线带宽低于水线时，离线业务可使用高带宽
- 在线带宽高于水线时，离线业务限用低带宽
- 判断间隔：10ms
示例
```bash
# bwmcli -s waterline 20mb
set waterline success

# bwmcli -p waterline
waterline is 20971520 (B)
```

**接口6：流量统计信息**
```
bwmcli -p stats  # 打印出向流量内部统计信息
bwmcli -P stats  # 打印入向流量内部统计信息
```
示例
```bash
# bwmcli -p stats
offline_target_bandwidth: 104857600
online_pkts: 982
offline_pkts: 0
online_rate: 28190
offline_rate: 0
```

**接口7：网卡状态查询**
```
bwmcli -p devs  # 描述系统上所有网卡的出向使能状态
bwmcli -P devs  # 描述系统上所有网卡的入向使能状态
```
示例
```bash
# bwmcli -p devs
lo              : disabled
enp2s2          : disabled
eth0            : egress enabled

# bwmcli -P devs
veth123456      : ingress enabled
```

### 典型使用案例
```bash
# 1. 查看当前网卡状态
bwmcli -p devs

# 2. 配置Pod出向QoS（假设Pod使用cgroup v1）
bwmcli -s /sys/fs/cgroup/net_cls/online 0      # 标记在线业务
bwmcli -s /sys/fs/cgroup/net_cls/offline -1    # 标记离线业务
bwmcli -e eth0                                   # 使能eth0出向QoS

# 3. 配置离线业务带宽限制
bwmcli -s bandwidth 20mb,1gb  # 设置带宽：低=20MB，高=1GB
bwmcli -s waterline 30mb      # 设置水线：30MB

# 4. 配置Pod入向QoS（宿主侧）
bwmcli -E veth123456          # 使能veth123456入向QoS
bwmcli -A 172.17.0.2          # 标记IP为离线流
bwmcli -R 172.17.0.2          # 移除离线标记

# 5. 查询配置
bwmcli -p bandwidth            # 查询出向带宽配置
bwmcli -p waterline           # 查询出水线配置
bwmcli -p stats               # 查看流量统计
```

## 默认配置值
| 参数 | 默认值 | 说明 |
|------|--------|------|
| 水线(waterline) | 20MB | 在线业务水线阈值 |
| 低带宽(low_rate) | 20MB | 水线触发时离线业务可用带宽 |
| 高带宽(high_rate) | 1GB | 水线未触发时离线业务可用带宽 |
| 判断间隔 | 10ms | 在线带宽是否超过水线的检测周期 |

## 带宽与水线限制
| 参数 | 最小值 | 最大值 |
|------|--------|--------|
| 带宽(bandwidth) | 1MB | 9999GB |
| 水线(waterline) | 20MB | 9999GB |

## 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request
