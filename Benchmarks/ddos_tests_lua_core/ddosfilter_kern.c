/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
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

	return tcph->dest;
}

static int parse_ipv4(void *data, uint64_t *nh_off, void *data_end)
{
	struct iphdr *iph = data + *nh_off;

	if (iph + 1 > data_end)
		return 0;

	*nh_off += iph->ihl * 4;

	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	return 22;
}

static int parse_eth(void *data, uint64_t *nh_off, void *data_end)
{
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return 0;

	*nh_off += sizeof(*eth);

	return eth->h_proto;
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int rc = XDP_PASS;
	u16 h_proto;
	uint64_t nh_off = 0;
	u32 ipproto;
	__u16 dport;

	h_proto = parse_eth(data, &nh_off, data_end);
	if (h_proto != htons(ETH_P_IP))
		return rc;

	rc = parse_ipv4(data, &nh_off, data_end);
	if (rc == XDP_PASS || !rc)
		return XDP_PASS;

	dport = parse_tcp(data, nh_off, data_end);
	if (htons(dport) == 80)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
