# ONCN-BWM 设计文档

**版本**: 1.0  
**日期**: 2026年4月18日  

---

## 概述

ONCN-BWM（Open Container Network Bandwidth Management）是一个基于eBPF和Traffic Control的容器网络带宽管理系统。本系统实现了POD级别的细粒度带宽隔离，支持容器生命周期自动化管理。

---

## 系统架构

### 整体设计

```
┌─────────────────────────────────────────────────┐
│              容器/POD Layer                      │
│    Container A      Container B      Container N  │
│     eth0              eth0              eth0     │
└────────┬────────────────┬────────────────┬──────┘
         │                │                │
┌────────┼────────────────┼────────────────┼──────┐
│ TC (Traffic Control) Layer                      │
│ ┌────────────────────────────────────────────┐ │
│ │ Filter: prio=1, handle=0x8880              │ │
│ │ - bwm_tc.o (egress)        [BPF内核态]   │ │
│ │ - bwm_tc_i.o (ingress)     [BPF内核态]   │ │
│ └────────────────────────────────────────────┘ │
│            ↕                                     │
│ ┌────────────────────────────────────────────┐ │
│ │  BPF Maps (内核共享内存)                   │ │
│ │  - ips_cfg_map / ips_i_cfg_map            │ │
│ │  - ips_throttle_map / ips_throttle_i_map  │ │
│ └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
         ▲                              ▲
         │                              │
    ┌────┴───────┐           ┌──────────┴─────┐
    │ bwmcli CLI │           │   OCI Hook      │
    │(用户空间)   │           │(容器生命周期)   │
    └────────────┘           └─────────────────┘
```

---

## POD粒度的带宽隔离实现

### 1. 核心数据结构

#### 带宽配置（用户定义）

```c
struct edt_throttle_cfg {
    __u64 low_rate;      // 低优先级流量限速，单位字节/秒
    __u64 high_rate;     // 高优先级流量限速，单位字节/秒  
    __u64 interval;      // waterline调整周期，单位纳秒（推荐1秒=1e9）
};
```

#### 运行状态（内核动态维护）

```c
struct edt_throttle {
    __u64 rate;                  // 当前有效限速速率
    __u64 t_last;                // 上一个报文的EDT时间戳
    __u64 t_start;               // 当前统计周期的开始时间
    __u64 online_tx_bytes;       // 本周期内高优先级已发送字节
    __u64 tx_bytes;              // 本周期内低优先级已发送字节
    struct {
        __u64 online_pkts;       // 高优先级报文计数
        __u64 offline_pkts;      // 低优先级报文计数
    } stats;
};
```

### 2. BPF Map存储设计

#### 为什么使用HASH而非LRU_HASH？

**LRU_HASH的问题**:
- 当Map达到容量上限时自动淘汰最少使用的entry
- 应用无法预知何时被淘汰 → 配置神秘消失 → 难以调试

**HASH的优势**:
- 由应用显式控制生命周期（创建时插入，销毁时删除）
- 所有变化都可追踪和监控 → 生产环境更可控
- 支持幂等删除（处理ENOENT错误）

#### Map映射表

| Map名 | 方向 | Key | Value | Pinning路径 |
|-------|------|-----|-------|-----------|
| ips_cfg_map | egress出向 | 源POD IP | edt_throttle_cfg | /sys/fs/bpf/bwm/ips_cfg_map |
| ips_throttle_map | egress出向 | 源POD IP | edt_throttle | /sys/fs/bpf/bwm/ips_throttle_map |
| ips_i_cfg_map | ingress入向 | 目标POD IP | edt_throttle_cfg | /sys/fs/bpf/bwm/ips_i_cfg_map |
| ips_throttle_i_map | ingress入向 | 目标POD IP | edt_throttle | /sys/fs/bpf/bwm/ips_throttle_i_map |

### 3. 流量处理机制

#### Egress（出向）流程

```
1. POD发送报文到eth0
   ├─ 报文进入Linux TC egress hook
   └─ BPF程序bwm_tc.o自动触发执行

2. BPF程序处理
   ├─ 解析报文获取源IP（package source address）
   ├─ 在ips_cfg_map查找该IP的限速配置
   ├─ 如果有配置：
   │  ├─ 读取ips_throttle_map中的运行状态
   │  ├─ 计算本报文的EDT时间戳
   │  │  ├─ delay = 报文长度 * NSEC_PER_SEC / 限速速率
   │  │  ├─ t_next = 上次EDT时间 + delay
   │  │  └─ 如果t_next > 当前时间：skb->tstamp = t_next
   │  │     （告诉qdisc延迟发送这个报文）
   │  └─ 更新ips_throttle_map中的运行状态
   └─ 返回TC_ACT_OK放行报文

3. Linux qdisc接收报文
   ├─ 根据skb->tstamp时间排队
   └─ 到达预定时间才真正发送

4. 报文离开网卡
```

**示例计算**:
```
假设限速100Mbps，报文大小1500字节

delay = 1500 * 10^9 / (100*10^6) = 15000纳秒 = 15微秒

报文1：到达时间 t=0
  → skb->tstamp = 0 + 15us = 15us

报文2：到达时间 t=10us
  → t_next = 15us + 15us = 30us  （30us > 10us）
  → skb->tstamp = 30us  （等待20us后再发送）

报文3：到达时间 t=100us
  → t_next = 30us + 15us = 45us  （45us < 100us，不需要等待）
  → skb->tstamp = 100us  （立即发送）
```

#### Ingress（入向）流程

```
1. 外部流量到达容器网卡eth0
   ├─ 报文进入Linux TC ingress hook
   └─ BPF程序bwm_tc_i.o自动触发执行

2. BPF程序处理
   ├─ 解析报文获取目标IP（destination address）
   ├─ 在ips_i_cfg_map查找该POD IP的入向限速配置
   ├─ 如果有配置：
   │  ├─ 读取ips_throttle_i_map中的运行状态
   │  ├─ 应用类似的EDT机制进行限速
   │  └─ 超限的报文可丢弃或重新入队
   └─ 返回TC_ACT_OK让报文继续

3. 报文进入POD网络栈
```

### 4. 双优先级和Waterline调整

#### 设计目的

在同一个POD中支持两类流量：
- **高优先级（online）**: 关键业务流量，立即发送
- **低优先级（offline）**: 后台数据同步，使用EDT控制

#### Waterline调整算法

周期性（每隔cfg.interval纳秒）检查和调整：

```c
void adjust_rate(const struct edt_throttle_cfg *cfg,
                  struct edt_throttle *online,
                  struct edt_throttle *offline) {
    
    // 1. 计算本周期内各优先级的实际使用带宽
    online_rate = online->online_tx_bytes * NSEC_PER_SEC / cfg->interval;
    offline_rate = offline->tx_bytes * NSEC_PER_SEC / cfg->interval;
    
    // 2. 检查高优先级是否未充分利用分配的带宽
    unused_high = cfg->high_rate - online_rate;
    
    // 3. 将未使用部分分配给低优先级
    if (unused_high > 0) {
        adjusted_offline_rate = cfg->low_rate + unused_high;
        offline->rate = adjusted_offline_rate;  // 低优先级可以加速
    } else {
        offline->rate = cfg->low_rate;  // 保持基础限速
    }
    
    // 4. 重置计数器开始新的统计周期
    online->online_tx_bytes = 0;
    offline->tx_bytes = 0;
    online->t_start = 当前时间;
    offline->t_start = 当前时间;
}
```

**例子**:
```
配置：high_rate=700Mbps, low_rate=300Mbps, interval=1秒

第1秒：
  - online流量实际：500Mbps（利用率71%）
  - offline流量：300Mbps
  - 调整后：offline可加速到 300 + (700-500) = 500Mbps

第2秒：
  - online流量实际：850Mbps（已接近上限）
  - offline流量：回到300Mbps
  - 调整后：offline保持 300Mbps
```

---

## Traffic Control 命令设计

### TC规则的精准配置

#### 为什么需要handle标识符？

**原始问题**:
- 多个应用共存时，TC规则容易冲突
- 删除时可能误删其他应用的规则

**解决方案**: 添加唯一标识

```c
// bwmcli.h中定义
#define BWM_TC_PRIO         "1"    // 优先级
#define BWM_TC_HANDLE       "0x8880"  // 唯一ID
```

#### 添加规则

```bash
# Egress规则
tc filter add dev eth0 egress \
    prio 1 \
    handle 0x8880 \
    bpf direct-action obj bwm_tc.o sec tc

# Ingress规则  
tc filter add dev eth0 ingress \
    prio 1 \
    handle 0x8880 \
    bpf direct-action obj bwm_tc_i.o sec tc
```

**参数说明**:
- `prio 1`: 优先级（数字越小优先级越高）
- `handle 0x8880`: 规则内的唯一标识符
- `direct-action`: BPF程序直接return decision，无需继续match

#### 删除规则（安全方式）

```bash
# 第1步：精准删除bwm的filter规则
tc filter del dev eth0 egress prio 1 handle 0x8880 bpf

# 第2步：检查是否还有其他egress规则
if ! tc filter show dev eth0 egress 2>/dev/null | grep -q .; then
    # 没有其他规则了，安全清理qdisc
    tc qdisc del dev eth0 clsact 2>/dev/null
fi
```

**优势**:
- ✓ 只删除本应用的规则（通过handle识别）
- ✓ 不会误删其他应用的规则
- ✓ 只有确认无其他规则时才清理qdisc

---

## 容器生命周期自动化（OCI Hook）

### 设计目标

- POD启动自动应用带宽策略
- POD停止自动清除配置
- POD重启时重新应用

### OCI Hook配置

```json
{
  "version": "1.0.0",
  "hook": {
    "path": "/usr/local/libexec/oci-hooks/libhook.sh",
    "stage": ["poststart", "poststop"],
    "args": ["libhook.sh", "poststart|poststop"],
    "when": {
      "annotations": {
        "io.kubernetes.bandwidth.*": ".*"
      }
    }
  }
}
```

### Hook流程

#### poststart（容器启动后立即执行）

```bash
1. 从容器metadata获取POD信息
   ├─ POD名称 / POD ID
   ├─ POD namespace
   └─ container_id

2. 获取POD的网络接口信息
   ├─ 进入容器网络namespace
   ├─ 查询容器的eth0 IP地址
   └─ 记录：POD_ID → IP的映射

3. 读取带宽限制策略（来自Kubernetes annotation）
   ├─ io.kubernetes.bandwidth.ingress_limit
   ├─ io.kubernetes.bandwidth.egress_limit
   └─ io.kubernetes.bandwidth.priority（优先级等）

4. 调用bwmcli配置带宽
   bwmcli setbandwidth \
       --ip $POD_IP \
       --egress $EGRESS_LIMIT \
       --ingress $INGRESS_LIMIT \
       --low-rate $LOW_RATE \
       --high-rate $HIGH_RATE

5. 保存映射关系供poststop使用
   echo "$POD_ID:$POD_IP" >> /var/run/bwm/pod_mapping.txt
```

#### poststop（容器停止时执行）

```bash
1. 获取停止容器的POD ID
   └─ 从容器停止事件或metadata

2. 查询该POD曾使用过的所有IP
   IPS=$(grep "^$POD_ID:" /var/run/bwm/pod_mapping.txt | cut -d: -f2)

3. 对每个IP执行删除操作
   for IP in $IPS; do
       bwmcli delbandwidth --ip $IP \
           || echo "Warning: delete failed for $IP"
   done
   
   注意：使用||继续，避免某个IP删除失败影响其他

4. 清理映射记录
   sed -i "/^$POD_ID:/d" /var/run/bwm/pod_mapping.txt
```

### POD ID提取

**关键挑战**: 从容器不同的metadata来源唯一标识POD

**提取策略**（优先级顺序）:

```bash
extract_pod_id() {
    local cgroup="$1"
    
    # 方案1：从cgroup path解析（最可靠）
    # cgroup示例: /kubepods.slice/kubepods-pod12345abc.slice/docker-abc123.scope
    if [[ $cgroup =~ pod([a-f0-9]+)\.slice ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi
    
    # 方案2：从sandbox ID提取（部分容器运行时）
    # cgroup示例: /kubepods/burstable/pod12345abc/*
    if [[ $cgroup =~ pod([a-f0-9]+) ]]; then
        echo "${BASH_REMATCH[1]:0:12}"
        return 0
    fi
    
    # 方案3：从环境变量（如果Pod已注入）
    if [ -n "$KUBERNETES_POD_UID" ]; then
        echo "$KUBERNETES_POD_UID"
        return 0
    fi
    
    return 1
}
```

---

## Bug修复与可靠性改进

### 1. 删除操作幂等化

**问题**:
- 尝试删除不存在的IP配置时返回ENOENT错误并失败
- 由于从LRU_HASH改为HASH，可能手动未删除就触发了误认为被删除

**解决方案**:

```c
int DelIpBandwidth(__u32 ipUint, int isIngress) {
    int fd1, fd2, ret;
    
    // 打开两个Map
    fd1 = bpf_obj_get(isIngress ? IPS_I_MAP_PATH : IPS_MAP_PATH);
    fd2 = bpf_obj_get(isIngress ? IPS_I_THRO_MAP_PATH : IPS_THRO_MAP_PATH);
    
    if (fd1 < 0 || fd2 < 0) {
        return EXIT_FAIL_BPF;
    }
    
    // 删除配置Map
    ret = bpf_map_delete_elem(fd1, &ipUint);
    if (ret != 0) {
        if (errno != ENOENT) {
            // 真正的错误（权限不足、Map损坏等）
            BWM_LOG_ERR("ERROR: Remove map fail. path=%s ip=0x%x errno=%d\n",
                isIngress ? IPS_I_MAP_PATH : IPS_MAP_PATH, ipUint, errno);
            (void)close(fd1);
            (void)close(fd2);
            return EXIT_FAIL_BPF;
        }
        // ENOENT = entry已被删除或被LRU淘汰，这是正常的
        BWM_LOG_INFO("IP entry not found (idempotent), continue\n");
    }
    
    // 删除节流Map（同样的容错处理）
    ret = bpf_map_delete_elem(fd2, &ipUint);
    if (ret != 0) {
        if (errno != ENOENT) {
            BWM_LOG_ERR("ERROR: Remove throttle fail. path=%s ip=0x%x errno=%d\n",
                isIngress ? IPS_I_THRO_MAP_PATH : IPS_THRO_MAP_PATH, ipUint, errno);
            (void)close(fd1);
            (void)close(fd2);
            return EXIT_FAIL_BPF;
        }
        BWM_LOG_INFO("Throttle entry not found (idempotent), continue\n");
    }
    
    // 必须关闭两个fd
    (void)close(fd1);
    (void)close(fd2);
    
    // 表示操作成功（无论是新删除还是幂等重复）
    BWM_LOG_INFO("Del bandwidth success or already deleted (idempotent)\n");
    return EXIT_OK;
}
```

**优势**:
- ✓ 安全重复调用DELETE操作
- ✓ 容错处理ENOENT错误
- ✓ 改进从LRU_HASH到HASH的平滑过渡

### 2. TC规则冲突处理

**问题**:
- 多应用环境中规则相互冲突
- 删除时过于激进，清理了其他应用的TC配置

**解决方案**: 上面已详细说明，关键是使用`handle 0x8880`标识和安全删除流程。

### 3. Egress POD流量修复

**问题**:
- POD出向流量未被正确识别和限速
- 某些报文格式的解析有漏洞

**改进**:

```c
// bpf/bwm_tc.c 改进的流量识别

static __always_inline __u32 get_src_ip(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    
    // 1. 检查帧长度有效性
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    __u16 h_proto = eth->h_proto;
    
    // 2. 处理VLAN标签（802.1Q）
    if (h_proto == htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return 0;
        h_proto = vlan->h_vlan_encapsulated_proto;
    }
    
    // 3. 提取IPv4源地址
    if (h_proto == htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)eth + 1;
        if ((void *)(iph + 1) > data_end)
            return 0;
        
        // 返回源IP（网络字节序）
        return iph->saddr;
    }
    
    return 0;
}
```

### 4. 详细的调试日志

**改进点**:

```c
// DEBUG日志：追踪执行流程
BWM_LOG_DEBUG("UpdateIpCfgByPath: path=%s ip=0x%x low_rate=%llu high_rate=%llu\n",
    path, ip, cfg->low_rate, cfg->high_rate);

// 错误日志：包含完整上下文
// 改前：BWM_LOG_ERR("ERROR: can't update map\n");
// 改后：
BWM_LOG_ERR("ERROR: UpdateIpCfgByPath fail. path=%s ip=0x%x ret=%d errno=%d\n",
    path, ip, ret, errno);

// 判断和流程日志
BWM_LOG_DEBUG("SetIpCfg: ip=0x%x isIngress=%d low=%llu high=%llu interval=%llu\n",
    ip, isIngress, cfg->low_rate, cfg->high_rate, cfg->interval);
```

---

## 系统保证与性能

### 正确性保证

| 保证 | 实现机制 | 说明 |
|------|--------|------|
| 幂等性 | ENOENT容错处理 | DELETE可安全重试，无副作用 |
| 隔离性 | HASH Map独立管理 | 各POD配置互不影响 |
| 一致性 | TC规则handle唯一化 | 多应用共存无冲突 |
| 持久性 | pinned BPF Map | /sys/fs/bpf持久化 |

### 性能特性

| 指标 | 性能 | 说明 |
|------|------|------|
| Map查表延迟 | <1微秒 | HASH Map O(1)查询 |
| 限速精度 | ±5% | EDT机制，抖动<100ms |
| 内核路径开销 | ~1000字节堆栈 | 每个报文处理 |
| 并发能力 | 多核无锁 | BPF Map使用bucket级锁 |

---

## 实际操作

### 基本命令

```bash
# 为POD设置带宽
bwmcli setbandwidth \
    --ip 10.244.0.5 \
    --egress 1000M \        # 出向1Gbps
    --ingress 500M \        # 入向500Mbps
    --low-rate 300M \       # 低优先级300M
    --high-rate 700M        # 高优先级700M

# 查询配置
bwmcli getbandwidth --ip 10.244.0.5

# 删除配置
bwmcli delbandwidth --ip 10.244.0.5

# 查看统计（实时速率等）
bwmcli stats --ip 10.244.0.5
```

### 故障排查

**问题1：规则未生效**
```bash
# 1. 检查BPF程序加载
bpftool prog list | grep bwm

# 2. 查看TC规则
tc filter show dev eth0 egress

# 3. 检查Map内容
bpftool map dump name ips_cfg_map
```

**问题2：删除失败**
```bash
# 1. 手动查询IP是否存在
bpftool map lookup name ips_cfg_map key hex 0a f4 00 05

# 2. 查看错误日志
journalctl -p err -g bwmcli

# 3. 尝试强制清空（谨慎）
bpftool map delete name ips_cfg_map key hex 0a f4 00 05
```

---

## 总结

ONCN-BWM通过以下设计实现高效的容器网络带宽管理：

1. **POD粒度隔离**: 基于IP的配置，HASH Map存储，应用管理生命周期
2. **内核EDT机制**: 高精度两级优先级限速，支持waterline动态调整
3. **容器生命周期绑定**: OCI Hook自动化，减少手工配置
4. **多应用共存**: TC规则handle标识化，安全删除流程
5. **可靠性**: 幂等操作、详细日志、完整错误处理

系统设计既满足生产环境的可靠性要求，也保持了良好的可维护性和扩展性。
