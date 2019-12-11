#define KBUILD_MODNAME "foo"

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <uapi/linux/bpf.h>
#include <net/ip.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "xdp_ssl_parser_common.h"

#define RANDLEN 32
#define SNIMAXLEN 253
#define MAXSSLEXTS 53
#define BLOCKEDSNI "test2.com.br"

/*
#define PIN_GLOBAL_NS 2
struct bpf_map_def SEC("maps") snimap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sslsni_wrapper),
	.max_entries = 1,
};
*/
struct bpf_map_def SEC("maps") rx_cnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") blocked_snis = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sslsni_wrapper),
	.max_entries = 10,
};

struct __attribute__((__packed__)) sslhdr1 {
	__u8  type;
	__u16 version;
	__u16 len;
};

struct  __attribute__((__packed__))sslhandshake {
	__u32 type:8,
	      len:24;
	__u16 version;
};

struct sslsession {
	__u8 len;
};

struct sslcipher {
	__u16 len;
};

struct exthdr {
	__u16 id;
	__u16 len;
	__u16 workaround;
};

struct  sniexthdr {
	__u16 len;
};

static char blocked_sni[] = "test2.com.br";

static int parse_ext(void *data, uint64_t *ext_off, void *data_end, __u16 *snilen)
{
	struct exthdr *sslext;
	__u16 *len;
	__u16 extlen;
	/* check possible access to offset outside of packet*/
	if (data + 1 > data_end)
		return -1;

	/* check that needed to be made to bypass verifier(possible bug?) */
	if (*ext_off > 2000)
		return -1;

	/* check that needed to be made to bypass verifier(possible bug?) */
	if (*ext_off < 1)
		return -1;

	data += *ext_off;
	sslext = (struct exthdr *) data;

	/* check possible access to offset outside of packet*/
	if (&(sslext->workaround) > data_end)
		return -1;

	extlen = bpf_htons(sslext->len);
	/* check that needed to be made to bypass verifier(possible bug?) */
	if (extlen > 2000)
		return -1;

	/* found server name extension header */
	if (bpf_htons(sslext->id) == 0) {
		/* check that needed to be made to bypass verifier(possible bug?) */
		if (*ext_off > 2000)
			return -1;

		len = data + 7;
		/* check possible access to offset outside of packet*/
		if (len + 1 > data_end)
			return -1;

		*snilen = bpf_htons(*len);
		return 1;
	}

	*ext_off += extlen + 4;

	/* check possible access to offset outside of packet*/
	if (data + 1 > data_end)
		return -1;

	return -2;
}

static int ssl(void *data, uint64_t ssl_off, void *data_end)
{
	struct sslhdr1 *sslh;
	struct sslhandshake *sslhsk;
	struct sslsession *sesh;
	struct sslcipher *sslci;
	uint64_t acc_off = ssl_off;
	struct exthdr *sslext;
	struct sniexthdr *snihdr;
	struct sniexthdr *snihdraux;
	struct sslsni_wrapper wrapper = {};
	int ret_parse_ext = 0;
	__u16 cilen = 10;
	__u16 snilen = 0;
	__u16 extlen = 0;
	u32 key_rx = 0;
	char *sslsni;
	long *cnt;

	sslh = data + acc_off;
	/* check possible access to offset outside of packet*/
	if (sslh + 1 > data_end)
		return XDP_PASS;

	/* check if content type is handshake*/
	if (sslh->type != 0x16)
		return XDP_PASS;
	acc_off += sizeof(struct sslhdr1);

	sslhsk = (void *) data + acc_off;

	/* check possible access to offset outside of packet*/
	if (sslhsk + 1 > data_end)
		return XDP_PASS;

	/* check if handshake type is Client Hello*/
	if (sslhsk->type != 0x01)
		return XDP_PASS;

	acc_off += sizeof(struct sslhandshake) + RANDLEN;

	sesh = (void *) data + acc_off;

	/* check possible access to offset outside of packet*/
	if (sesh + 1 > data_end)
		return XDP_PASS;

	acc_off += sizeof(struct sslsession) + sesh->len;
	sslci = (void *) data + acc_off;

	/* check possible access to offset outside of packet*/
	if (sslci + 1 > data_end)
		return XDP_PASS;

	cilen = bpf_htons(sslci->len);
	/* check that needed to be made to bypass verifier(possible bug?) */
	if (cilen > 2000)
		return XDP_PASS;

	acc_off += sizeof(struct sslcipher) + cilen + 4;
	//#pragma clang loop unroll(full)
	for (int i = 0; i < MAXSSLEXTS; i++) {
		ret_parse_ext = parse_ext(data, &acc_off, data_end, &snilen);
		/* found server name extension header */
		if(ret_parse_ext == 1)
			break;
		/* one of the checks in parse_ext function failed*/
		else if(ret_parse_ext == -1)
			return XDP_PASS;

		/* check that needed to be made to bypass verifier(possible bug?) */
		if (acc_off > 2000)
			return XDP_PASS;
	}

	/* check that needed to be made to bypass verifier(possible bug?) */
	if (acc_off > 2000)
		return XDP_PASS;

	data += acc_off;
	/* check possible access to offset outside of packet*/
	if (data + 11 > data_end)
		return XDP_PASS;
	sslsni = data + 9;

	if (sslsni == NULL) {
		return XDP_PASS;
	}

	char fmt[] = "sslsni %s\n";
	cnt = bpf_map_lookup_elem(&rx_cnt, &key_rx);
	if (!cnt) {
		return XDP_PASS;
	}
	(*cnt)++;

	//return XDP_DROP;
	/*
	char blocked_sni[] = "test2.com.br";
	unsigned char *proxy = blocked_sni;
	if (strncmp(BLOCKEDSNI, sslsni, snilen) == 0) {
		return XDP_DROP;
	}
	if (sslsni[0] == 't')
		return XDP_DROP;
	if (snilen > 100)
		return XDP_PASS;
	*/

	if (sslsni + 15 > data_end)
		return XDP_PASS;

	/*
	if (strcmp(sslsni, fmt2->sslsni) == 0) 
		return XDP_DROP;
	if (strncmp(sslsni, fmt, sizeof(fmt)) == 0)
		return XDP_DROP;
	*/
	
	int key = 1;
	struct sslsni_wrapper *fmt2;
	fmt2 = bpf_map_lookup_elem(&blocked_snis, &key);
	if (fmt2 == NULL)
		return XDP_PASS;

	for (int i = 0; i < 14; i++) {
		if (sslsni + 1 < data_end) {
			if (sslsni[i] != fmt2->sslsni[i])
				return XDP_PASS;

			if (sslsni[i] == 0) {
				return XDP_DROP;
			}
		}
	}

	/*
	#pragma clang loop unroll(full)
	for (int i = 0; i < 100; i++) {
		if (i == snilen) {
			//wrapper.sslsni[i] = '\0';
			//bpf_map_update_elem(&snimap, &key, &wrapper, BPF_ANY);
			break;
		}

		if (sslsni + 1 > data_end)
			return XDP_PASS;

		if (blocked_sni[i] != *sslsni) {
			return XDP_PASS;
		}
		wrapper.sslsni[i] = *sslsni;
		sslsni += 1;
	}
	*/

	return XDP_PASS;
}

static int tcp(void *data, uint64_t tp_off, void *data_end)
{
	struct tcphdr *tcp = data + tp_off;

	if (tcp + 1 > data_end)
		return 0;

	return ssl(data, tp_off + tcp->doff * 4, data_end);
}

static int parse_ipv4(void *data, uint64_t nh_off, void *data_end)
{

	struct iphdr *iph = data + nh_off;
	uint64_t ihl_len;

	if (iph + 1 > data_end)
		return 0;

	ihl_len = iph->ihl * 4;
	return tcp(data, nh_off + ihl_len, data_end);
}

SEC("sslparser")
int handle_ingress(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_PASS;
	long *value;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP))
		return parse_ipv4(data, nh_off, data_end);

	return rc;
}
char _license[] SEC("license") = "GPL";

