#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include "bpf_helpers.h"
#define RATEMAX 100000
#define NANOSEC_IN_SEC 1000000000

struct bpf_map_def SEC("maps") rx_cnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 1,
};

static u32 key = 0;

static int tcp(struct xdp_md *ctx, void *data, uint64_t tp_off, void *data_end, __u32 src_ip)
{
	unsigned char *pkt;
	struct tcphdr *tcp = data + tp_off;
	long *cnt;

	if (tcp + 1 > data_end)
		return XDP_PASS;

	if (tcp->dest != htons(80))
		return XDP_PASS;

	cnt = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!cnt)
		return XDP_DROP;

	(*cnt)++;

	return XDP_DROP;
}

static int parse_ipv4(struct xdp_md *ctx, void *data, uint64_t nh_off, void *data_end)
{
	struct iphdr *iph;
	uint64_t ihl_len;
	int key_ip = 2;

	iph = data + nh_off;
	if (iph + 1 > data_end)
		return 0;

	ihl_len = iph->ihl * 4;

	if (iph->protocol == IPPROTO_TCP)
		return tcp(ctx, data, nh_off + ihl_len, data_end, iph->saddr);

	return XDP_PASS;
}

SEC("sslparser")
int xdp_parse_http(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	u16 h_proto;
	uint64_t nh_off = 0;
	struct ethhdr *eth = data;
	int rc = XDP_PASS;

	if(eth + 1 > data_end)
		return rc;

	h_proto = eth->h_proto;
	nh_off += sizeof(struct ethhdr);
	if (h_proto != htons(ETH_P_IP))
			return rc;

	return parse_ipv4(ctx, data, nh_off, data_end);
}

char _license[] SEC("license") = "GPL";
