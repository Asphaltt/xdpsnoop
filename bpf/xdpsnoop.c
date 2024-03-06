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
    u8 is_dev_attach;
    u8 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct xdp_install_args {
    struct net_device *dev;
    struct netdev_bpf *bpf;
    char errmsg[64];
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

struct xdp_dev_attach_args {
    struct net_device *dev;
    struct netlink_ext_ack *extack;
    struct bpf_xdp_link *link;
    struct bpf_prog *new_prog;
    struct bpf_prog *old_prog;
    char errmsg[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct xdp_dev_attach_args);
    __uint(max_entries, 1);
} xdp_dev_attach SEC(".maps");

static __always_inline struct xdp_dev_attach_args *
get_dev_attach_args(void)
{
    u32 key = 0;

    return bpf_map_lookup_elem(&xdp_dev_attach, &key);
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
output_bpf(struct event *ev, struct bpf_prog *prog)
{
    BPF_CORE_READ_INTO(&ev->prog_id, prog, aux, id);
    bpf_probe_read_kernel_str(ev->prog, sizeof(ev->prog), BPF_CORE_READ(prog, aux, name));
}

static __always_inline void
output_errmsg(struct event *ev, int retval, struct netlink_ext_ack *extack, char *msg)
{
    if (retval == 0)
        return;

    if (extack)
        bpf_probe_read_kernel_str(ev->errmsg, sizeof(ev->errmsg), BPF_CORE_READ(extack, _msg));
    else if (msg)
        bpf_probe_read_kernel_str(ev->errmsg, sizeof(ev->errmsg), msg);
}

SEC("kretprobe")
int BPF_KRETPROBE(kr_xdp_install, int retval)
{
    struct xdp_install_args *args;
    struct netdev_bpf *bpf;

    args = get_install_args();
    if (!args || !args->dev || !args->bpf)
        return BPF_OK;

    struct event ev = {};

    output_netdev(&ev, args->dev);
    bpf = args->bpf;
    output_bpf(&ev, BPF_CORE_READ(bpf, prog));
    ev.retval = retval;
    output_errmsg(&ev, retval, BPF_CORE_READ(bpf, extack), args->errmsg);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    clear_install_args(args);

    return BPF_OK;
}

SEC("kprobe")
int BPF_KPROBE(k_dev_xdp_attach, struct net_device *dev,
               struct netlink_ext_ack *extack, struct bpf_xdp_link *link,
               struct bpf_prog *new_prog, struct bpf_prog *old_prog)
{
    struct xdp_dev_attach_args *args;

    args = get_dev_attach_args();
    if (!args)
        return BPF_OK;

    args->dev = dev;
    args->extack = extack;
    args->link = link;
    args->new_prog = new_prog;
    args->old_prog = old_prog;

    return BPF_OK;
}

SEC("kretprobe")
int BPF_KRETPROBE(kr_dev_xdp_attach, int retval)
{
    struct xdp_dev_attach_args *args;

    args = get_dev_attach_args();
    if (!args || !args->dev)
        return BPF_OK;

    struct event ev = {};

    ev.is_dev_attach = 1;
    output_netdev(&ev, args->dev);
    ev.retval = retval;
    output_errmsg(&ev, retval, args->extack, args->errmsg);
    if (args->new_prog) {
        output_bpf(&ev, args->new_prog);
    } else {
        struct bpf_xdp_link *link = args->link;
        output_bpf(&ev, BPF_CORE_READ(link, link.prog));
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    return BPF_OK;
}

SEC("kprobe")
int BPF_KPROBE(k_do_trace_netlink_extack, const char *msg)
{
    struct xdp_dev_attach_args *attach_args;
    struct xdp_install_args *install_args;
    struct netdev_bpf *bpf;

    attach_args = get_dev_attach_args();
    if (attach_args && !attach_args->extack)
        bpf_probe_read_kernel_str(attach_args->errmsg, sizeof(attach_args->errmsg), msg);

    install_args = get_install_args();
    if (install_args && (bpf = install_args->bpf) && !BPF_CORE_READ(bpf, extack))
        bpf_probe_read_kernel_str(install_args->errmsg, sizeof(install_args->errmsg), msg);

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
