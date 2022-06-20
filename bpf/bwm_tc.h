/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: Network bandwidth management tool
 */
#ifndef __BWM_TC_H__
#define __BWM_TC_H__

#define THROTTLE_MAP_PATH 	"/sys/fs/bpf/tc/globals/throttle_map"
#define THROTTLE_CFG_PATH 	"/sys/fs/bpf/tc/globals/throttle_cfg"

#undef NSEC_PER_SEC
#undef NSEC_PER_MSEC

#define NSEC_PER_SEC (1000000000ULL)
#define NSEC_PER_MSEC (1000000ULL) // NSEC_PER_MSEC * 10 = 1s

#define DEFAULT_LOW_BANDWIDTH	(20LL * 1024 * 1024)
#define DEFAULT_HIGH_BANDWIDTH	(1LL * 1024 * 1024 * 1024)
#define DEFAULT_WATERLINE	(20LL * 1024 * 1024)
#define LOWEST_BANDWIDTH	(1LL * 1024 * 1024)
#define HIGHEST_BANDWIDTH	(9999LL * 1024 * 1024 * 1024)

struct throttle_stats {
	unsigned long long check_times;
	unsigned long long high_times;
	unsigned long long low_times;

	unsigned long long online_pkts;
	unsigned long long offline_pkts;
	unsigned long long offline_prio;

	unsigned long long rate_past;
	unsigned long long offline_rate_past;
};

struct edt_throttle_cfg {
	unsigned long long water_line;
	unsigned long long interval;
	unsigned long long low_rate;
	unsigned long long high_rate;
};

struct edt_throttle {
	unsigned long long t_last;
	unsigned long long rate;

	unsigned long long tx_bytes;
	unsigned long long online_tx_bytes;
	unsigned long long t_start;

	struct throttle_stats stats;
};

#endif
