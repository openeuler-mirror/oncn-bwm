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
│  bwmcli.c
│  bwmcli.h
│  CMakeLists.txt
│  LICENSE
│  README.md
│
├─bpf # Contains three eBPF program files that implement the bandwidth management logic
│
└─tools # Online/offline bandwidth monitoring tools built on bpftrace
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

**Interface 1**

Description

```bash
bwmcli –e/-d ethx # Enable/disable QoS on a specific NIC
bwmcli –e/-d      # Enable/disable QoS on all NICs
bwmcli -E/-D ethx # Enable/disable ingress QoS on a specific NIC
bwmcli –E/-D      # Enable/disable ingress QoS on all NICs
```

Example

```bash
# bwmcli –e eth0 –e eth1
enable eth0 success
enable eth1 success

# bwmcli –d eth0 –d eth1
disable eth0 success
disable eth1 success
```

**Interface 2**

Description (for egress)

```bash
bwmcli –s path <prio> # Set the network priority for a specific cgroup
bwmcli –p path        # Query the network priority of a specific cgroup
```

Example

```bash
# bwmcli -s /sys/fs/cgroup/net_cls/test_online 0
set prio success

# bwmcli -p /sys/fs/cgroup/net_cls/test_online
prio is 0
```

**Interface 3**

Description (for ingress)

```bash
bwmcli –A 172.17.0.2 # Classify the ingress traffic for the specified IP address as offline
bwmcli –R 172.17.0.2 # Classify the ingress traffic for the specified IP address as online
```

Example

```bash
# bwmcli –A 172.17.0.2
AddIp 172.17.0.2 success
# bwmcli –R 172.17.0.2
RemoveIp 172.17.0.2 success
```

**Interface 4**

Description

```bash
bwmcli –s bandwidth <low,high> # Set the offline bandwidth
bwmcli –p bandwidth            # Query the offline bandwidth
bwmcli –S bandwidth <low,high> # Set the ingress offline bandwidth
bwmcli –P bandwidth            # Query the ingress offline bandwidth
```

Example

```bash
# bwmcli -s bandwidth 30mb,100mb
set bandwidth success
# bwmcli -S bandwidth 30mb,100mb
set bandwidth success

# bwmcli -p bandwidth
bandwidth is 31457280(B),104857600(B)
# bwmcli -P bandwidth
bandwidth is 31457280(B),104857600(B)
```

**Interface 5**

Description

```bash
bwmcli –s waterline <val> # Set the online traffic watermark
bwmcli –p waterline       # Query the online traffic watermark
bwmcli –S waterline <val> # Set the ingress online traffic watermark
bwmcli –P waterline       # Query the ingress online traffic watermark
```

Example

```bash
# bwmcli -s waterline 20mb
set waterline success
# bwmcli -S waterline 20mb
set waterline success

# bwmcli -p waterline
waterline is 20971520 (B)
# bwmcli -P waterline
waterline is 20971520 (B)
```

**Interface 6**

Description

```bash
bwmcli –p stats # Print internal statistics for egress traffic
bwmcli –P stats # Print internal statistics for ingress traffic
```

Example

```bash
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

**Interface 7**

Description

```bash
bwmcli –p devs # Print the enablement status of all NICs on the system
```

Example

```bash
# bwmcli –p devs
lo              : disabled
enp2s2          : disabled

# bwmcli –P devs
lo              : disabled
enp2s2          : disabled
```

### Typical Use Cases

```bash
bwmcli -p devs # Query the current enablement status of all NICs on the system
bwmcli -s /sys/fs/cgroup/net_cls/online 0
bwmcli -s /sys/fs/cgroup/net_cls/offline -1
bwmcli -e eth0 # Enable QoS on the eth0 interface
bwmcli -s bandwidth 20mb,1gb # Configure the offline service bandwidth limits
bwmcli -s waterline 30mb # Configure the online traffic watermark
bwmcli -E veth123456 # Enable QoS on the host-side veth123456 (corresponding to Pod ingress traffic)
bwmcli –A 172.17.0.2 # Classify ingress traffic destined for the target IP address as offline
bwmcli –R 172.17.0.2 # Remove the offline classification of ingress traffic for the target IP address
```

## Contribution

1. Fork this repository.
2. Create a Feat_*xxx* branch.
3. Commit code.
4. Create a pull request (PR).

## Notes

Use the file naming pattern `README_xx.md` to indicate a supported language (for example, `README_EN.md`).
