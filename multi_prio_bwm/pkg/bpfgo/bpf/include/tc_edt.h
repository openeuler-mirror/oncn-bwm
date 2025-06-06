#ifndef _TC_EDT_H_
#define _TC_EDT_H_

#define CUSTOM_MARK_SKB 1

#define NSEC_PER_SEC (1000000000ULL)
#define MAX_DELAY_STAMP (10000000000ULL)
#define MAX_MAP_SIZE 5000
#define MAX_PROCESS_SIZE 1000
#define MAX_IP_SIZE 5000

struct throttle_cfg {
	__u32 priority;  // 实例优先级，使用0,1,2表示，值越大优先级越高，默认为0
	__u32 interval;  // 统计保温周期，默认10ms
	__u64 low_rate;  // 最低保障带宽
	__u64 high_rate; // 最高限制带宽，当前暂未使用
	__u64 req_rate;  // 针对当前带宽情况设置的请求带宽，实时调整，初始值等于low_rate
};

struct throttle_stat {
	__u64 t_last;     // 上一个数据包的发送时间
	__u64 t_start;    // 当前采样周期开始时间
	__u64 rate;       // 当前实例的带宽速率
	__u64 tx_bytes;   // 周期内报文大小统计
	__u64 total_pkts; // 累计总包数量
};

struct id_key {
	__u32 ip;
	__u32 port; // for host process flow, specific port mark is required, for pod flow, the port defaults to 0
};

struct src_dst_port {
	__u32 source;
	__u32 dest;
};

#define SPLIT_ID_PRIORITY(id_priority, priority, id)	\
    do {												\
        (priority) = (id_priority) & 0xffff;			\
        (id) = (id_priority) >> 16 & 0xffff;			\
    } while (0)


#if CUSTOM_MARK_SKB == 0

// egress maps
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct throttle_cfg);
	__uint(max_entries, MAX_MAP_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct throttle_stat);
	__uint(max_entries, MAX_MAP_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_stat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct id_key);
	__type(value, __u32); // high 16 bits: id, low 16 bits: priority
	__uint(max_entries, MAX_MAP_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_id SEC(".maps");

// ingress maps
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct throttle_cfg);
	__uint(max_entries, MAX_MAP_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct throttle_stat);
	__uint(max_entries, MAX_MAP_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_stat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct id_key);
	__type(value, __u32); // high 16 bits: id, low 16 bits: priority
	__uint(max_entries, MAX_MAP_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_id SEC(".maps");

#else

#define PIN_GLOBAL_NS 2

struct bpf_elf_map_t {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
	__u32 inner_idx;
};

// egress maps
struct bpf_elf_map_t SEC("maps") egress_cfg = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct throttle_cfg),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAX_MAP_SIZE,
    .flags = 0,
    .id = 0,
};

struct bpf_elf_map_t SEC("maps") egress_stat = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct throttle_stat),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAX_MAP_SIZE,
    .flags = 0,
    .id = 0,
};

struct bpf_elf_map_t SEC("maps") egress_id = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct id_key),
    .value_size = sizeof(__u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAX_MAP_SIZE,
    .flags = 0,
    .id = 0,
};

// ingress maps
struct bpf_elf_map_t SEC("maps") ingress_cfg = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct throttle_cfg),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAX_MAP_SIZE,
    .flags = 0,
    .id = 0,
};

struct bpf_elf_map_t SEC("maps") ingress_stat = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct throttle_stat),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAX_MAP_SIZE,
    .flags = 0,
    .id = 0,
};

struct bpf_elf_map_t SEC("maps") ingress_id = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct id_key),
    .value_size = sizeof(__u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAX_MAP_SIZE,
    .flags = 0,
    .id = 0,
};
#endif

#endif // _TC_EDT_H_
