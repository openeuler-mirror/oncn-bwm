#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "include/common.h"
#include "include/tc_edt.h"

static void stat_init(const struct throttle_cfg *cfg, struct throttle_stat *stat)
{
	stat->t_last = 0;
	stat->t_start = bpf_ktime_get_ns();
	stat->rate = cfg->low_rate;
	stat->tx_bytes = 0;
}

static int statistics_and_edt_packet(struct __sk_buff *skb, struct throttle_cfg *cfg, struct throttle_stat *stat)
{
	unsigned long long t_cur;
	unsigned long long t_send;
	unsigned long long t_delay;
	unsigned long long t_next;
	unsigned long long t_last = stat->t_last;

	__sync_fetch_and_add(&stat->tx_bytes, skb->len);
	__sync_fetch_and_add(&stat->total_pkts, 1);

	// 1. EDT schedule departure
	t_cur = bpf_ktime_get_ns();
	t_send = skb->tstamp;

	if (t_send < t_cur)
		t_send = t_cur;

	if ((skb->sk) && (bpf_tcp_sock(skb->sk) == NULL) && (t_last > t_cur) && ((t_last - t_cur) > MAX_DELAY_STAMP))
		return TC_ACT_SHOT;

	t_delay = skb->len * NSEC_PER_SEC / cfg->req_rate;
	t_next = stat->t_last + t_delay;

	if (t_next <= t_send) {
		stat->t_last = t_send;
		return TC_ACT_OK;
	}

	skb->tstamp = t_next;
	stat->t_last = t_next;
	return TC_ACT_OK;
}

static void update_rate(const struct throttle_cfg *cfg, struct throttle_stat *stat)
{
	unsigned long long t_cur;
	unsigned long long t_past;

	t_cur = bpf_ktime_get_ns();
	t_past = t_cur - stat->t_start;
	if (t_past > cfg->interval) {
		stat->t_start = t_cur;
		stat->rate = stat->tx_bytes * NSEC_PER_SEC / t_past;

		/* we can safety update without lock */
		if (stat->t_start == t_cur)
			stat->tx_bytes = 0;
	}
}

static struct iphdr* get_iphdr(struct __sk_buff *skb)
{
	// skb->remote_ip4 is not visiable to tc, we need parse dest_ip from skb handly
	// https://github1s.com/libbpf/libbpf-bootstrap/blob/HEAD/examples/c/tc.bpf.c#L12
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eth;
	struct iphdr *ip;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return NULL;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return NULL;

	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return NULL;

	return ip;
}

static struct tcphdr* get_tcphdr(struct __sk_buff *skb, struct iphdr *ip)
{
	struct tcphdr *tcp;
	void *data_end = (void *)(__u64)skb->data_end;

	tcp = (struct tcphdr *)(ip + 1);
	if ((void *)(tcp + 1) > data_end)
		return NULL;

	return tcp;
}

static struct udphdr* get_udphdr(struct __sk_buff *skb, struct iphdr *ip)
{
	struct udphdr *udp;
	void *data_end = (void *)(__u64)skb->data_end;

	udp = (struct udphdr *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return NULL;

	return udp;
}

static int get_src_dst_port(struct __sk_buff *skb, struct iphdr *iph, struct src_dst_port *ports)
{
	struct tcphdr *tcp;
	struct udphdr *udp;

	if (iph->protocol == IPPROTO_TCP) {
		//bpf_printk("get_dest_port tcp pkt\n");
		tcp = get_tcphdr(skb, iph);
		if (tcp) {
			ports->source = tcp->source;
			ports->dest = tcp->dest;
			return 0;
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		//bpf_printk("get_dest_port udp pkt\n");
		udp = get_udphdr(skb, iph);
		if (udp) {
			ports->source = udp->source;
			ports->dest = udp->dest;
			return 0;
		}
	} else {
		//bpf_printk("get_dest_port other pkt\n");
		return -1;
	}

	return -1;
}

static int egress_edt_handle(struct __sk_buff *skb, int id_priority)
{
	int ret = TC_ACT_OK;
	unsigned int priority = 0;
	unsigned int id = 0;
	struct throttle_cfg *cfg = NULL;
	struct throttle_stat *stat = NULL;

	SPLIT_ID_PRIORITY(id_priority, priority, id);
	//bpf_printk("egress:id=%u, priority=%u\n", id, priority);
	cfg = bpf_map_lookup_elem(&egress_cfg, &id);
	if (cfg == NULL)
		return TC_ACT_OK;

	stat = bpf_map_lookup_elem(&egress_stat, &id);
	if (stat == NULL)
		return TC_ACT_OK;

	if (stat->rate == 0)
		stat_init(cfg, stat);

	ret = statistics_and_edt_packet(skb, cfg, stat);
	update_rate(cfg, stat);
	//bpf_printk("stat->rate: %u\n", stat->rate);

	return ret;
}

static int ingress_edt_handle(struct __sk_buff *skb, int id_priority)
{
	int ret = TC_ACT_OK;
	unsigned int priority = 0;
	unsigned int id = 0;
	struct throttle_cfg *cfg = NULL;
	struct throttle_stat *stat = NULL;

	SPLIT_ID_PRIORITY(id_priority, priority, id);
	//bpf_printk("ingress:id=%u, priority=%u\n", id, priority);
	cfg = bpf_map_lookup_elem(&ingress_cfg, &id);
	if (cfg == NULL)
		return TC_ACT_OK;

	stat = bpf_map_lookup_elem(&ingress_stat, &id);
	if (stat == NULL)
		return TC_ACT_OK;

	if (stat->rate == 0)
		stat_init(cfg, stat);

	ret = statistics_and_edt_packet(skb, cfg, stat);
	update_rate(cfg, stat);
	//bpf_printk("stat->rate: %u\n", stat->rate);

	return ret;
}

SEC("tc_egress")
int bwm_tc_egress(struct __sk_buff *skb)
{
	int ret = TC_ACT_OK;
#if CUSTOM_MARK_SKB == 0
	int *id_priority = NULL;
	struct id_key key = {0};
	struct iphdr *ip;
	struct src_dst_port ports = {0};
	ip = get_iphdr(skb);
	if (ip == NULL)
		return ret;
	key.ip = ip->saddr;
	//bpf_printk("egress:pod finding key.ip=%u\n", key.ip);

	id_priority = bpf_map_lookup_elem(&egress_id, &key);
	if (id_priority != NULL) {
		//bpf_printk("egress:get pod id_priority\n");
		//bpf_printk("egress:ip=%u\n", key.ip);
		return egress_edt_handle(skb, *id_priority);
	}

	ret = get_src_dst_port(skb, ip, &ports);
	if (ret == 0) {
		// as server, use the IP and Port of local server as the key
		key.ip = ip->saddr;
		key.port = ports.source;
		//bpf_printk("as server, egress:process finding key.ip=%u, key.port=%u\n", key.ip, key.port);
		id_priority = bpf_map_lookup_elem(&egress_id, &key);
		if (id_priority != NULL) {
			//bpf_printk("as server, egress:get process id_priority\n");
			//bpf_printk("as server, egress:ip=%u, port=%u\n", key.ip, key.port);
			return egress_edt_handle(skb, *id_priority);
		}

		// as client, use the IP and Port of remote server as the key
		key.ip = ip->daddr;
		key.port = ports.dest;
		id_priority = bpf_map_lookup_elem(&egress_id, &key);
		if (id_priority != NULL) {
			//bpf_printk("as client, egress:get process id_priority\n");
			//bpf_printk("as client, egress:ip=%u, port=%u\n", key.ip, key.port);
			return egress_edt_handle(skb, *id_priority);
		}
	}

#else
	if (skb->priority != 0) {
		ret = egress_edt_handle(skb, skb->priority);
		skb->priority = 0;
		return ret;
	}
#endif
	// default stream
	return egress_edt_handle(skb, 0);
}

SEC("tc_ingress")
int bwm_tc_ingress(struct __sk_buff *skb)
{
	int ret = TC_ACT_OK;
#if CUSTOM_MARK_SKB == 0
	int *id_priority = NULL;
	struct iphdr *ip;
	struct src_dst_port ports = {0};
	struct id_key key = {0};

	ip = get_iphdr(skb);
	if (ip == NULL)
		return ret;

	key.ip = ip->daddr;
	//bpf_printk("ingress:pod finding key.ip=%u\n", key.ip);

	id_priority = bpf_map_lookup_elem(&ingress_id, &key);
	if (id_priority != NULL) {
		//bpf_printk("ingress:get pod id_priority\n");
		//bpf_printk("ingress:ip=%u, port=%u\n", key.ip, port);
		return ingress_edt_handle(skb, *id_priority);
	}

	ret = get_src_dst_port(skb, ip, &ports);
	if (ret == 0) {
		// as server, use the IP and Port of local server as the key
		key.ip = ip->daddr;
		key.port = ports.dest;
		//bpf_printk("as client, ingress:process finding key.ip=%u, key.port=%u\n", key.ip, key.port);
		id_priority = bpf_map_lookup_elem(&ingress_id, &key);
		if (id_priority != NULL) {
			//bpf_printk("as server, ingress:get process id_priority\n");
			//bpf_printk("as server, ingress:ip=%u, port=%u\n", key.ip, port);
			return ingress_edt_handle(skb, *id_priority);
		}

		// as client, use the IP and Port of remote server as the key
		key.ip = ip->saddr;
		key.port = ports.source;
		id_priority = bpf_map_lookup_elem(&ingress_id, &key);
		if (id_priority != NULL) {
			//bpf_printk("as client, ingress:get process id_priority\n");
			//bpf_printk("as client, ingress:ip=%u, port=%u\n", key.ip, port);
			return ingress_edt_handle(skb, *id_priority);
		}
	}

#else
	if (skb->priority != 0) {
		ret = ingress_edt_handle(skb, skb->priority);
		skb->priority = 0;
		return ret;
	}
#endif
	// default stream
	return ingress_edt_handle(skb, 0);
}

char _license[] SEC("license") = "GPL";
