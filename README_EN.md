# oncn-bwm

## Overview

By distinguishing between online and offline services, this feature guarantees the required bandwidth for online services while maximizing the utilization of total network bandwidth resources.
The specific capabilities provided are as follows.

### Pod Network Priority Configuration

#### Egress

1. Configure the network priority of a specific cgroup by executing the `bwmcli` command. The parameters required for this command include `cgrp_path` and `prio`.
2. The default priority value is `0`, designating online services. `-1` designates offline services.

#### Ingress

1. Configure the network priority for packets destined for a specific target IP address by executing the `bwmcli` command. The parameter required for this command includes `ip`.
2. Unconfigured IP addresses default to online services, while configured IP addresses are designated as offline services.

### Offline Service Network Bandwidth Throttling

1. Pod network bandwidth limits apply globally to all offline services. The aggregate bandwidth of all offline services cannot exceed the configured limit, whereas online services are not subject to the bandwidth restrictions.
2. Configure the offline service network bandwidth limits for a host or virtual machine by executing the `bwmcli` command. The required parameters for this command include the allowed minimum bandwidth (KB/MB/GB) and maximum bandwidth (KB/MB/GB).
3. The bandwidth throttling feature works with the watermark mechanism to manage offline traffic. When the online service bandwidth is below the configured watermark, offline services are permitted to burst up to the specified maximum bandwidth. Conversely, when online traffic exceeds the watermark, offline services are throttled down to the specified minimum bandwidth.

### Online Service Watermark Configuration

1. Configure the online service watermark for a host or virtual machine by executing the `bwmcli` command. The required parameter for this command is the watermark value (KB/MB/GB).
2. When the aggregate bandwidth of all online services on a host exceeds the watermark, the system restricts the bandwidth available to offline services. Conversely, when the total online bandwidth drops below the watermark, the bandwidth allocation for offline services increases.
3. The system evaluates whether the total online service bandwidth has crossed the watermark threshold every 10 ms. Bandwidth limits applied to offline services are adjusted based on the online traffic statistics collected within each 10 ms window.

### Pod Network QoS Enablement/Disablement

1. Enable or disable the QoS feature on a network interface card (NIC) by executing the `bwmcli` command. The required parameter is the NIC name. If no NIC name is specified, the operation applies to all NICs on the host by default.
2. All QoS-enabled NICs on a single host are treated as a unified pool internally, meaning they collectively share the configured watermark and network bandwidth limits.

## Software Architecture

```bash
oncn-bwm
│  bwmcli.c          # bwmcli command-line tool
│  bwmcli.h          # Header file and constant definitions
│  CMakeLists.txt
│  LICENSE
│  README.md
│
├─bpf                # eBPF programs implementing bandwidth management logic
│  ├─bwm_prio_kern.c # cgroup priority setting program, sets packet priority via cgroup_skb/egress hook
│  ├─bwm_tc.c        # egress bandwidth management TC program, distinguishes online/offline traffic by cgroup classid
│  ├─bwm_tc_i.c      # ingress bandwidth management TC program, distinguishes online/offline traffic by parsing destination IP
│  ├─bwm_tc.h        # shared data structure definitions (bandwidth config, throttle state, statistics)
│  └─bwm_tc_common.h # inline helper functions (online/offline traffic processing, rate adjustment, throttle init)
│
└─tools              # Online/offline bandwidth monitoring tools built on bpftrace
```

## Installation

1. cmake
2. make
3. mkdir -p /usr/share/bwmcli
4. install -Dpm 0500 bpf/CMakeFiles/bwm_prio_kern.dir/bwm_prio_kern.c.o /usr/share/bwmcli/bwm_prio_kern.o
5. install -Dpm 0500 bpf/CMakeFiles/bwm_tc.dir/bwm_tc.c.o /usr/share/bwmcli/bwm_tc.o
6. install -Dpm 0500 bpf/CMakeFiles/bwm_tc_i.dir/bwm_tc_i.c.o /usr/share/bwmcli/bwm_tc_i.o
7. install -Dpm 0500 bwmcli /usr/bin
8. install -Dpm 0500 tools/bwm_monitor.bt /usr/bin
9. install -Dpm 0500 tools/bwm_monitor_ingress.bt /usr/bin

## Instructions

### Interface Description

**Interface 1: NIC QoS Enable/Disable**

```bash
bwmcli -e/-d ethx    # Enable/disable egress QoS on a specific NIC
bwmcli -e/-d         # Enable/disable egress QoS on all NICs
bwmcli -E/-D ethx    # Enable/disable ingress QoS on a specific NIC
bwmcli -E/-D         # Enable/disable ingress QoS on all NICs
bwmcli -v            # Display version number
```

Example

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

**Interface 2: Cgroup Priority Setting (Egress)**

```bash
bwmcli -s path <prio>  # Set priority for a cgroup (supports cgroup v1/v2)
bwmcli -p path         # Query priority for a cgroup
```
- Priority 0 = online service, -1 = offline service
- cgroup v1 path example: `/sys/fs/cgroup/net_cls/xxx`
- cgroup v2 path example: `/sys/fs/cgroup/xxx`

Example

```bash
# bwmcli -s /sys/fs/cgroup/net_cls/test_online 0
set prio success

# bwmcli -p /sys/fs/cgroup/net_cls/test_online
prio is 0
```

**Interface 3: IP Priority Setting (Ingress)**

```bash
bwmcli -A <ip>  # Mark ingress traffic for IP as offline
bwmcli -R <ip>  # Mark ingress traffic for IP as online
```
- Unconfigured IPs default to online service

Example

```bash
# bwmcli -A 172.17.0.2
AddIp 172.17.0.2 success
# bwmcli -R 172.17.0.2
RemoveIp 172.17.0.2 success
```

**Interface 4: Bandwidth Limit Setting**

```bash
bwmcli -s bandwidth <low,high>  # Set egress offline bandwidth
bwmcli -p bandwidth              # Query egress offline bandwidth
bwmcli -S bandwidth <low,high>  # Set ingress offline bandwidth
bwmcli -P bandwidth              # Query ingress offline bandwidth
```
- Bandwidth range: 1MB ~ 9999GB
- low: low bandwidth for offline (used when watermark triggered)
- high: high bandwidth for offline (used when watermark not triggered)

Example

```bash
# bwmcli -s bandwidth 30mb,100mb
set bandwidth success

# bwmcli -p bandwidth
bandwidth is 31457280(B),104857600(B)
```

**Interface 5: Watermark Setting**

```bash
bwmcli -s waterline <val>  # Set egress online watermark
bwmcli -p waterline        # Query egress online watermark
bwmcli -S waterline <val>  # Set ingress online watermark
bwmcli -P waterline        # Query ingress online watermark
```
- Watermark range: 20MB ~ 9999GB
- When online bandwidth is below watermark, offline can use high bandwidth
- When online bandwidth exceeds watermark, offline is limited to low bandwidth
- Check interval: 10ms

Example

```bash
# bwmcli -s waterline 20mb
set waterline success

# bwmcli -p waterline
waterline is 20971520 (B)
```

**Interface 6: Traffic Statistics**

```bash
bwmcli -p stats  # Print egress traffic internal statistics
bwmcli -P stats  # Print ingress traffic internal statistics
```

Example

```bash
# bwmcli -p stats
offline_target_bandwidth: 104857600
online_pkts: 982
offline_pkts: 0
online_rate: 28190
offline_rate: 0
```

**Interface 7: NIC Status Query**

```bash
bwmcli -p devs  # Show egress enablement status of all NICs
bwmcli -P devs  # Show ingress enablement status of all NICs
```

Example

```bash
# bwmcli -p devs
lo              : disabled
enp2s2          : disabled
eth0            : egress enabled

# bwmcli -P devs
veth123456      : ingress enabled
```

### Typical Use Cases

```bash
# 1. Check current NIC status
bwmcli -p devs

# 2. Configure Pod egress QoS (assuming Pod uses cgroup v1)
bwmcli -s /sys/fs/cgroup/net_cls/online 0      # Mark online service
bwmcli -s /sys/fs/cgroup/net_cls/offline -1    # Mark offline service
bwmcli -e eth0                                   # Enable eth0 egress QoS

# 3. Configure offline service bandwidth limits
bwmcli -s bandwidth 20mb,1gb  # Set bandwidth: low=20MB, high=1GB
bwmcli -s waterline 30mb      # Set watermark: 30MB

# 4. Configure Pod ingress QoS (host side)
bwmcli -E veth123456          # Enable veth123456 ingress QoS
bwmcli -A 172.17.0.2          # Mark IP as offline flow
bwmcli -R 172.17.0.2          # Remove offline marking

# 5. Query configuration
bwmcli -p bandwidth            # Query egress bandwidth config
bwmcli -p waterline           # Query watermark config
bwmcli -p stats               # View traffic statistics
```

## Default Configuration Values

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| Watermark | 20MB | Online service watermark threshold |
| Low bandwidth (low_rate) | 20MB | Offline bandwidth when watermark triggered |
| High bandwidth (high_rate) | 1GB | Offline bandwidth when watermark not triggered |
| Check interval | 10ms | Period for checking if online bandwidth exceeds watermark |

## Bandwidth and Watermark Limits

| Parameter | Minimum | Maximum |
|-----------|---------|---------|
| Bandwidth | 1MB | 9999GB |
| Watermark | 20MB | 9999GB |

## Contribution

1. Fork this repository.
2. Create a Feat_*xxx* branch.
3. Commit code.
4. Create a pull request (PR).
