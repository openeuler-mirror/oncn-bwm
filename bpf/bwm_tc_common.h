/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: Network bandwidth management tool
 */
#ifndef __BWM_TC_COMMON_H__
#define __BWM_TC_COMMON_H__

#include <bpf/bpf_helpers.h>

#ifndef BWM_DEBUG  // Define BWM_DEBUG to enable debugging
#undef bpf_printk
#define bpf_printk(fmt, ...)
#endif

#define PIN_GLOBAL_NS 2
#define OFFLINE_PRIO ((unsigned int)-1)

struct bpf_elf_map_t {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_elem;
	__u32 flags;
	__u32 id; 
	__u32 pinning;
};

static inline void bwm_online(const struct __sk_buff *skb, struct edt_throttle *throttle)
{
	__sync_fetch_and_add(&throttle->online_tx_bytes, skb->len);
	__sync_fetch_and_add(&throttle->stats.online_pkts, 1);
}

static inline void bwm_offline(struct __sk_buff *skb, struct edt_throttle *throttle)
{
	unsigned long long t_cur;
	unsigned long long t_send;
	unsigned long long t_delay;
	unsigned long long t_next;

	__sync_fetch_and_add(&throttle->tx_bytes, skb->len);
	__sync_fetch_and_add(&throttle->stats.offline_pkts, 1);

	// 1. EDT schedule departure
	t_cur = bpf_ktime_get_ns();
	t_send = skb->tstamp;

	if (t_send < t_cur)
		t_send = t_cur;

	t_delay = skb->len * NSEC_PER_SEC / throttle->rate;
	t_next = throttle->t_last + t_delay;

	if (t_next <= t_send) {
		throttle->t_last = t_send;
		return;
	}

	skb->tstamp = t_next;
	throttle->t_last = t_next;
	return;
}


static inline void adjust_rate(const struct edt_throttle_cfg *cfg, struct edt_throttle *throttle)
{
	unsigned long long t_cur;
	unsigned long long t_past;
	unsigned long long rate_past;
	unsigned long long offline_rate_past;

	// 2. check if need to adjust offline speed
	t_cur = bpf_ktime_get_ns();
	t_past = t_cur - throttle->t_start;
	if (t_past > cfg->interval) {
		throttle->t_start = t_cur;
		rate_past = throttle->online_tx_bytes * NSEC_PER_SEC / t_past;
		offline_rate_past = throttle->tx_bytes * NSEC_PER_SEC / t_past;

		if (rate_past >= cfg->water_line) {
			throttle->rate = cfg->low_rate;
			__sync_fetch_and_add(&throttle->stats.low_times, 1);
		} else {
			throttle->rate = cfg->high_rate;
			__sync_fetch_and_add(&throttle->stats.high_times, 1);
		}

		/* we can safety update without lock */
		if (throttle->t_start == t_cur) {
			throttle->online_tx_bytes = 0;
			throttle->tx_bytes = 0;
		}

		throttle->stats.rate_past = rate_past;
		throttle->stats.offline_rate_past = offline_rate_past;
		__sync_fetch_and_add(&throttle->stats.check_times, 1);
	}
}

static inline void throttle_init(const struct edt_throttle_cfg *cfg,
			      struct edt_throttle *throttle)
{
	throttle->t_last = 0;
	throttle->rate = cfg->low_rate;

	throttle->tx_bytes = 0;
	throttle->t_start = 0;
}

#endif
