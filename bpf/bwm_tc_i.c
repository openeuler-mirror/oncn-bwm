/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: Network bandwidth management tool
 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/netdevice.h>
#include <bpf/bpf_endian.h>

#include "bwm_tc.h"
#include "bwm_tc_common.h"

struct bpf_elf_map_t SEC("maps") throttle_i_cfg = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct edt_throttle_cfg),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 1,
	.flags = 0,
	.id = 0,
};

struct bpf_elf_map_t SEC("maps") throttle_i_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct edt_throttle),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 1,
	.flags = 0,
	.id = 0,
};

struct bpf_elf_map_t SEC("maps") ips_i_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(__u32), // ipv4
	.value_size = sizeof(int),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = IPS_MAX_NUM,
	.flags = 0,
	.id = 0,
};

SEC("tc")
int bwm_tc(struct __sk_buff *skb)
{
	struct edt_throttle *throttle = NULL;
	struct edt_throttle_cfg * cfg = NULL;
	unsigned int map_index = 0;
	unsigned long ip = 0;
	int *prio = NULL;

	cfg = bpf_map_lookup_elem(&throttle_i_cfg, &map_index);
	if (cfg == NULL)
		return TC_ACT_OK;

	throttle = bpf_map_lookup_elem(&throttle_i_map, &map_index);
	if (throttle == NULL)
		return TC_ACT_OK;
	const struct edt_throttle_cfg * cfg_con = cfg;
	if (throttle->rate == 0)
		throttle_init(cfg_con, throttle);

	// skb->remote_ip4 is not visiable to tc, we need parse dest_ip from skb handly
	// https://github1s.com/libbpf/libbpf-bootstrap/blob/HEAD/examples/c/tc.bpf.c#L12
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	ip = l3->daddr;

	const struct __sk_buff *skb_con = skb;
	prio = bpf_map_lookup_elem(&ips_i_map, &ip);
	if (prio != NULL) {
		// matched: offline flow
		bwm_offline(skb, throttle);
	} else {
		// dismatched: online flow
		bwm_online(skb_con, throttle);
	}
	adjust_rate(cfg_con, throttle);

	bpf_printk("[tc.c]dest_ip=%u\n", ip);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
