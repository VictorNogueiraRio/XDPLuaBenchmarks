#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"

static int parse_tcp(void *data, uint64_t tcp_off, void *data_end)
{
	struct tcphdr *tcph = data + tcp_off;

	if (tcph + 1 > data_end)
		return 0;

	return tcph->source;
}

static int parse_ipv4(void *data, uint64_t *nh_off, void *data_end)
{
	struct iphdr *iph = data + *nh_off;

	if (iph + 1 > data_end)
		return 0;

	*nh_off += iph->ihl * 4;

	return iph->protocol;
}

static int parse_eth(void *data, uint64_t *nh_off, void *data_end)
{
	struct ethhdr *eth = data;
	if (data + *nh_off > data_end)
		return 0;

	nh_off += sizeof(*eth);

	return eth->h_proto;
}

SEC("ddos")
int xdp_ddos(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int rc = XDP_PASS;
	long *value;
	u16 h_proto;
	uint64_t nh_off = 0;
	u32 ipproto;
	u16 sport;

	h_proto = parse_eth(data, &nh_off, data_end);
	if (h_proto != htons(ETH_P_IP))
		return rc;

	ipproto = parse_ipv4(data, &nh_off, data_end);
	if (ipproto != 6)
		return rc;

	sport = parse_tcp(data, nh_off, data_end);
	if (sport == 1234)
		return XDP_DROP;

	return rc;
}

char _license[] SEC("license") = "GPL";
