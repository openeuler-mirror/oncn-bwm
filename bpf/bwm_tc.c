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

SEC("tc")
int bwm_tc(struct __sk_buff *skb)
{
	struct edt_throttle *throttle = NULL;
	struct edt_throttle_cfg * cfg = NULL;
	unsigned int map_index = 0;
	unsigned int priority_index = 0;

	cfg = bpf_map_lookup_elem(&throttle_cfg, &map_index);
	if (cfg == NULL)
		return TC_ACT_OK;

	throttle = bpf_map_lookup_elem(&throttle_map, &map_index);
	if (throttle == NULL)
		return TC_ACT_OK;
	const struct edt_throttle_cfg * cfg_con = cfg;
	if (throttle->rate == 0)
		throttle_init(cfg_con, throttle);

	priority_index = bpf_skb_cgroup_classid(skb);
	skb->priority += priority_index;

	const struct __sk_buff *skb_con = skb;
	/* online, we should be careful of SO_PRIORITY option. */
	if (skb->priority != OFFLINE_PRIO)
		bwm_online(skb_con, throttle);
	else
		bwm_offline(skb, throttle);

	adjust_rate(cfg_con, throttle);

	bpf_printk("[tc.c]prio=%u\n", skb->priority);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
