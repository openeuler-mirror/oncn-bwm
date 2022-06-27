/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: Network bandwidth management tool
 */

#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


#ifndef BWM_DEBUG  // Define BWM_DEBUG to enable debugging
#undef bpf_printk
#define bpf_printk(fmt, ...)
#endif

#define ALLOW_PKT 1

#define DEFAULT_CGP_PRIO 0

struct bpf_map_def cgrp_prio SEC("maps")  = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(unsigned int),
	.max_entries = 1,
	.map_flags = 0,
};

SEC("cgroup_skb/egress")
int _bwm_out_cg(struct __sk_buff *skb)
{
	unsigned int queue_index = 0;
	unsigned int *prio;

	prio = bpf_map_lookup_elem(&cgrp_prio, &queue_index);
	if (prio == NULL) {
		skb->priority = DEFAULT_CGP_PRIO;
		return ALLOW_PKT;
	}

	skb->priority = *prio;
	bpf_printk("[kern.c]prio=%u\n", skb->priority);

	return ALLOW_PKT;
}

char _license[] SEC("license") = "GPL";
