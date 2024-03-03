// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */


#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"

struct event {
    u32 ifindex;
    char ifname[16];
    int32 retval;
    char errmsg[64];
    u32 prog_id;
    char prog[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct xdp_install_args {
    struct net_device *dev;
    struct netdev_bpf *bpf;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct xdp_install_args);
    __uint(max_entries, 1);
} xdp_install SEC(".maps");

static __always_inline struct xdp_install_args *
get_install_args(void)
{
    u32 key = 0;

    return bpf_map_lookup_elem(&xdp_install, &key);
}

static __always_inline void
clear_install_args(struct xdp_install_args *args)
{
    args->dev = NULL;
    args->bpf = NULL;
}

static __always_inline bool
is_setup_xdp(struct netdev_bpf *bpf)
{
    return BPF_CORE_READ(bpf, command) == XDP_SETUP_PROG;
}

SEC("kprobe")
int BPF_KPROBE(k_xdp_install, struct net_device *dev, struct netdev_bpf *bpf)
{
    struct xdp_install_args *args;

    args = get_install_args();
    if (!args)
        return BPF_OK;

    if (!is_setup_xdp(bpf)) {
        clear_install_args(args);
        return BPF_OK;
    }

    args->dev = dev;
    args->bpf = bpf;

    return BPF_OK;
}

static __always_inline void
output_netdev(struct event *ev, struct net_device *dev)
{
    BPF_CORE_READ_INTO(&ev->ifindex, dev, ifindex);
    bpf_probe_read_kernel_str(ev->ifname, sizeof(ev->ifname), dev->name);
}

static __always_inline void
output_bpf(struct event *ev, struct netdev_bpf *bpf)
{
    BPF_CORE_READ_INTO(&ev->prog_id, bpf, prog, aux, id);
    bpf_probe_read_kernel_str(ev->prog, sizeof(ev->prog), BPF_CORE_READ(bpf, prog, aux, name));
}

static __always_inline void
output_errmsg(struct event *ev, int retval, struct netdev_bpf *bpf)
{
    if (retval == 0)
        return;

    bpf_probe_read_kernel_str(ev->errmsg, sizeof(ev->errmsg), ev->errmsg);
}

SEC("kretprobe")
int BPF_KRETPROBE(kr_xdp_install, int retval)
{
    struct xdp_install_args *args;

    args = get_install_args();
    if (!args || !args->dev || !args->bpf)
        return BPF_OK;

    struct event ev = {};

    output_netdev(&ev, args->dev);
    output_bpf(&ev, args->bpf);
    ev.retval = retval;
    output_errmsg(&ev, retval, args->bpf);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
