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
│  bwmcli.c # bwmcli命令行工具
│  bwmcli.h
│  CMakeLists.txt
│  LICENSE
│  README.md
│
├─bpf # 三个ebpf程序文件实现带宽管理逻辑
│
└─tools # 在离线带宽检测工具，基于bpftrace
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
**接口1**

说明
```
bwmcli –e/-d ethx 使能/除能某个网卡的Qos功能
bwmcli –e/-d 使能/除能所有网卡的Qos功能
bwmcli -E/-D ethx 使能/除能某个网卡的入向Qos功能
bwmcli –E/-D 使能/除能所有网卡的入向Qos功能
```
示例
```
# bwmcli –e eth0 –e eth1
enable eth0 success
enable eth1 success

# bwmcli –d eth0 –d eth1
disable eth0 success
disable eth1 success
```

**接口2**

说明(用于出向)
```
bwmcli –s path <prio> 设置某个cgroup的优先级
bwmcli –p path 查询某个cgroup的优先级
```
示例
```
# bwmcli -s /sys/fs/cgroup/net_cls/test_online 0
set prio success

# bwmcli -p /sys/fs/cgroup/net_cls/test_online
prio is 0
```

**接口3**	

说明(用于入向)
```
bwmcli –A 172.17.0.2 标识对应ip入向流为离线流量
bwmcli –R 172.17.0.2 标识对应ip入向流为在线流量
```
示例	
```
# bwmcli –A 172.17.0.2
AddIp 172.17.0.2 success
# bwmcli –R 172.17.0.2
RemoveIp 172.17.0.2 success
```

**接口4**	

说明
```
bwmcli –s bandwidth <low,high> 设置离线带宽
bwmcli –p bandwidth 查询离线带宽
bwmcli –S bandwidth <low,high> 设置入向离线带宽
bwmcli –P bandwidth 查询入向离线带宽
```
示例
```
# bwmcli -s bandwidth 30mb,100mb
set bandwidth success
# bwmcli -S bandwidth 30mb,100mb
set bandwidth success

# bwmcli -p bandwidth
bandwidth is 31457280(B),104857600(B)
# bwmcli -P bandwidth
bandwidth is 31457280(B),104857600(B)
```

**接口5**	

说明
```
bwmcli –s waterline <val> 设置在线水线
bwmcli –p waterline 查询在线水线
bwmcli –S waterline <val> 设置入向在线水线
bwmcli –P waterline 查询入向在线水线
```
示例	
```
# bwmcli -s waterline 20mb
set waterline success
# bwmcli -S waterline 20mb
set waterline success

# bwmcli -p waterline
waterline is 20971520 (B)
# bwmcli -P waterline
waterline is 20971520 (B)
```

**接口6**	

说明
```
bwmcli –p stats 打印出向流量内部统计信息
bwmcli –P stats 打印入向流量内部统计信息
```
示例
```
# bwmcli -p stats
offline_target_bandwidth: 104857600
online_pkts: 982
offline_pkts: 0
online_rate: 28190
offline_rate: 0

# bwmcli –P stats
offline_target_bandwidth: 1073741824
online_pkts: 1150
offline_pkts: 0
online_rate: 27306
offline_rate: 0
```

**接口7**	

说明
```
bwmcli –p devs 描述系统上所有网卡的使能状态
```
示例	
```
# bwmcli –p devs
lo              : disabled
enp2s2          : disabled

# bwmcli –P devs
lo              : disabled
enp2s2          : disabled
```

### 典型使用案例
```
bwmcli -p devs 查询系统当前网卡使能状态
bwmcli -s /sys/fs/cgroup/net_cls/online 0
bwmcli -s /sys/fs/cgroup/net_cls/offline -1
bwmcli -e eth0 使能eth0的网卡 Qos功能
bwmcli -s bandwidth 20mb,1gb 配置离线业务带宽
bwmcli -s waterline 30mb 配置在线业务的水线
bwmcli -E veth123456 使能veth123456的网卡(宿主侧) Qos功能(对应pod入向流量)
bwmcli –A 172.17.0.2 配置目标ip标识入向离线流
bwmcli –R 172.17.0.2 删除目标ip标识入向离线流
```

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
