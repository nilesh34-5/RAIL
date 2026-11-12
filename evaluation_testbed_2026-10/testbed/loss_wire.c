/* Wire-level packet-loss emulator for the RAIL two-node testbed (tc eBPF).
 *
 * Why this exists: the testbed kernel ships without sch_netem, so netem cannot
 * be used.  This program reproduces the two netem loss models used in the
 * paper, at the same place netem would act (a qdisc hook on the wire), and is
 * attached to the egress of the wire-namespace port that faces G_B.  It is
 * NOT part of RAIL; it only plays the role of a lossy link.
 *
 *   LOSS_MODE 0  no loss (counts frames only)
 *   LOSS_MODE 1  Bernoulli (independent) loss with probability P_LOSS
 *   LOSS_MODE 2  Gilbert-Elliott two-state loss, netem "gemodel" semantics:
 *                  GE_P  = P(Good -> Bad)   GE_R = P(Bad -> Good)
 *                  GE_H1 = loss prob in Bad (1-h),  GE_K1 = loss prob in Good (1-k)
 *                mean loss = (GE_P*GE_H1 + GE_R*GE_K1) / (GE_P + GE_R)
 *
 * Probabilities are compile-time constants scaled to 2^32 (u32), so the fast
 * path does no map lookups except the state/counter maps.  Only IPv4 UDP
 * frames to UDP port RAIL_PORT are subjected to loss; everything else passes,
 * so the experiment harness can still observe the wire.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef LOSS_MODE
#define LOSS_MODE 0
#endif
#ifndef P_LOSS
#define P_LOSS 0u
#endif
#ifndef GE_P
#define GE_P 0u
#endif
#ifndef GE_R
#define GE_R 0u
#endif
#ifndef GE_H1
#define GE_H1 0xFFFFFFFFu
#endif
#ifndef GE_K1
#define GE_K1 0u
#endif
#ifndef RAIL_PORT
#define RAIL_PORT 52080
#endif

/* key 0: frames seen, 1: frames dropped, 2: GE state (0 good / 1 bad) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} loss_state SEC(".maps");

static __always_inline void add(__u32 k)
{
    __u64 *v = bpf_map_lookup_elem(&loss_state, &k);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("tc")
int tc_loss(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->ihl < 5 || ip->ihl > 15 || ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    void *l4 = (void *)ip + ip->ihl * 4;
    if (l4 + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;
    struct udphdr *udp = l4;
    if (udp->dest != bpf_htons(RAIL_PORT))
        return TC_ACT_OK;

    add(0);
#if LOSS_MODE == 1
    if (bpf_get_prandom_u32() < P_LOSS) {
        add(1);
        return TC_ACT_SHOT;
    }
#elif LOSS_MODE == 2
    __u32 k2 = 2;
    __u64 *st = bpf_map_lookup_elem(&loss_state, &k2);
    if (!st)
        return TC_ACT_OK;
    __u32 u = bpf_get_prandom_u32();
    if (*st == 0) {                     /* Good */
        if (u < GE_P) *st = 1;
    } else {                            /* Bad */
        if (u < GE_R) *st = 0;
    }
    __u32 v = bpf_get_prandom_u32();
    if ((*st == 1 && v < GE_H1) || (*st == 0 && v < GE_K1)) {
        add(1);
        return TC_ACT_SHOT;
    }
#endif
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
