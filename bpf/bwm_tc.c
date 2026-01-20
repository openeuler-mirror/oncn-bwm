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

struct bpf_elf_map_t SEC("maps") throttle_cfg = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct edt_throttle_cfg),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 1,
	.flags = 0,
	.id = 0,
};

struct bpf_elf_map_t SEC("maps") throttle_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct edt_throttle),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 1,
	.flags = 0,
	.id = 0,
};

struct bpf_elf_map_t SEC("maps") ips_cfg_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(__u32), // ipv4
	.value_size = sizeof(struct edt_throttle_cfg),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = IPS_MAX_NUM,
	.flags = 0,
	.id = 0,
	};

struct bpf_elf_map_t SEC("maps") ips_throttle_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct edt_throttle),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = IPS_MAX_NUM,
	.flags = 0,
	.id = 0,
};

SEC("tc")
int bwm_tc(struct __sk_buff *skb)
{
	struct edt_throttle *throttle = NULL;
	struct edt_throttle *ips_throttle = NULL;
	struct edt_throttle_cfg * cfg = NULL;
	struct edt_throttle_cfg * ips_cfg = NULL;
	unsigned int map_index = 0;
	unsigned int priority_index = 0;
	unsigned long ip = 0;

	cfg = bpf_map_lookup_elem(&throttle_cfg, &map_index);
	if (cfg == NULL)
		return TC_ACT_OK;

	throttle = bpf_map_lookup_elem(&throttle_map, &map_index);
	if (throttle == NULL)
		return TC_ACT_OK;

	struct edt_throttle_cfg * cfg_con = cfg;
	if (throttle->rate == 0)
		throttle_init(cfg_con, throttle);

	priority_index = bpf_skb_cgroup_classid(skb);
	skb->priority += priority_index;

	const struct __sk_buff *skb_con = skb;
	/* online, we should be careful of SO_PRIORITY option. */
	if (skb->priority != OFFLINE_PRIO){
		struct iphdr *l3 = getiphdr(skb);
			if (l3 == NULL)
				return TC_ACT_OK;
		ip = l3->saddr;
		ips_cfg = bpf_map_lookup_elem(&ips_cfg_map, &ip);
		if (ips_cfg != NULL) {
			ips_throttle = bpf_map_lookup_elem(&ips_throttle_map, &ip);
			if (ips_throttle != NULL) {
				cfg_con->high_rate = ips_cfg->high_rate;
				cfg_con->low_rate = ips_cfg->low_rate;
				throttle = ips_throttle;
			}
		}
		bwm_offline(skb, throttle);
	}
	else
		bwm_online(skb_con, throttle);
	adjust_rate(cfg_con, throttle);

	bpf_printk("[tc.c]prio=%u\n", skb->priority);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
