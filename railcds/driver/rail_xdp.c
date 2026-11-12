/* RAIL driver-layer enforcement (Linux, eBPF).
 *
 * Implements the "Driver Layer" row of Table I in the paper. Scholz et al.
 * (cited in Sec. III-A) show that programs attached through the eXpress Data
 * Path discard frames "before socket buffers are even allocated" - earlier, and
 * far cheaper, than netfilter. This file provides that layer.
 *
 * Two programs, because XDP is receive-side only:
 *
 *   xdp_rail_ingress   attached with XDP at the NIC driver. Passes ONLY IPv4
 *                      UDP from the configured peer to the configured port;
 *                      drops everything else, including ARP and all of IPv6.
 *
 *   tc_rail_egress     attached to the clsact egress qdisc, since XDP cannot
 *                      see transmitted frames. On the receiver this drops
 *                      everything unconditionally (no reverse channel at all);
 *                      on the sender it permits only the RAIL flow.
 *
 * Configuration is compile-time so no map lookups sit in the fast path:
 *   RAIL_PEER_IP    peer address as a big-endian u32 (see loader)
 *   RAIL_PORT       RAIL UDP port, host byte order
 *   RAIL_ROLE_RECV  1 on the receiver, 0 on the sender
 *
 * A per-CPU counter map records passed/dropped frames so the enforcement can be
 * checked (see `railcds.cli driverfilter --status`).
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef RAIL_PEER_IP
#define RAIL_PEER_IP 0          /* 0 = accept any source (loader should set it) */
#endif
#ifndef RAIL_PORT
#define RAIL_PORT 52080
#endif
#ifndef RAIL_ROLE_RECV
#define RAIL_ROLE_RECV 1
#endif

enum {
    CNT_PASS_IN = 0,
    CNT_DROP_IN = 1,
    CNT_PASS_OUT = 2,
    CNT_DROP_OUT = 3,
    CNT_MAX = 4,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} rail_counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&rail_counters, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

/* ------------------------------------------------------------------ *
 * Ingress: XDP, at the driver, before an sk_buff exists.
 * ------------------------------------------------------------------ */
SEC("xdp")
int xdp_rail_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto drop;

    /* Only IPv4 survives. This alone removes ARP and the whole of IPv6,
     * whose neighbour discovery is inherently bidirectional.             */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto drop;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto drop;
    /* Bound ihl explicitly: the verifier will not infer the 4-bit width, and
     * an unbounded header length makes the later l4 offset unprovable.    */
    if (ip->ihl < 5 || ip->ihl > 15)
        goto drop;

    /* Drops ICMP, TCP (SSH/SMB/HTTP), and every non-UDP protocol.        */
    if (ip->protocol != IPPROTO_UDP)
        goto drop;

#if RAIL_PEER_IP != 0
    if (ip->saddr != bpf_htonl(RAIL_PEER_IP))
        goto drop;
#endif

    /* The sender accepts nothing at all on the diode NIC.                */
#if !RAIL_ROLE_RECV
    goto drop;
#else
    void *l4 = (void *)ip + ip->ihl * 4;
    if (l4 + sizeof(struct udphdr) > data_end)
        goto drop;
    struct udphdr *udp = l4;
    if (udp->dest != bpf_htons(RAIL_PORT))
        goto drop;

    bump(CNT_PASS_IN);
    return XDP_PASS;
#endif

drop:
    bump(CNT_DROP_IN);
    return XDP_DROP;
}

/* ------------------------------------------------------------------ *
 * Egress: tc clsact. XDP has no transmit hook, so the outbound half of
 * the boundary is enforced here.
 * ------------------------------------------------------------------ */
SEC("tc")
int tc_rail_egress(struct __sk_buff *skb)
{
#if RAIL_ROLE_RECV
    /* Nothing leaves the receiver on this interface: no ACKs, no ICMP
     * errors, no ARP replies, no application traffic. This is what makes
     * the link unidirectional.                                           */
    bump(CNT_DROP_OUT);
    return TC_ACT_SHOT;
#else
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto shot;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto shot;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto shot;
    if (ip->ihl < 5 || ip->ihl > 15)
        goto shot;
    if (ip->protocol != IPPROTO_UDP)
        goto shot;

#if RAIL_PEER_IP != 0
    if (ip->daddr != bpf_htonl(RAIL_PEER_IP))
        goto shot;
#endif

    void *l4 = (void *)ip + ip->ihl * 4;
    if (l4 + sizeof(struct udphdr) > data_end)
        goto shot;
    struct udphdr *udp = l4;
    if (udp->dest != bpf_htons(RAIL_PORT))
        goto shot;

    bump(CNT_PASS_OUT);
    return TC_ACT_OK;

shot:
    bump(CNT_DROP_OUT);
    return TC_ACT_SHOT;
#endif
}

char _license[] SEC("license") = "GPL";
