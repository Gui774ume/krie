/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SETSOCKOPT_H_
#define _SETSOCKOPT_H_

struct bpf_filter_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u16 family;
    u16 type;
    u16 protocol;
    u16 prog_len;
    u32 bpf_filter_cmd;
};

memory_factory(bpf_filter_event)

#define SO_ATTACH_FILTER	26
#define SO_DETACH_FILTER	27
#define SO_LOCK_FILTER		44

SYSCALL_KPROBE3(setsockopt, int, fd, int, level, int, optname) {
    // handle bpf_filter events
    if (optname == SO_ATTACH_FILTER || optname == SO_DETACH_FILTER || optname == SO_LOCK_FILTER) {
        struct syscall_cache_t syscall = {
            .type = EVENT_BPF_FILTER,
            .bpf_filter = {
                .bpf_filter_cmd = optname,
            }
        };
        cache_syscall(&syscall);
    }
    return 0;
}

__attribute__((always_inline)) int sys_setsockopt_ret(void *ctx, int retval) {
    // handle bpf_filter events
    struct syscall_cache_t *syscall = pop_syscall(EVENT_BPF_FILTER);
    if (syscall) {
        struct bpf_filter_event_t *event = new_bpf_filter_event();
        if (event == NULL) {
            // should never happen
            return 0;
        }
        event->event.retval = retval;
        event->bpf_filter_cmd = syscall->bpf_filter.bpf_filter_cmd;
        event->family = syscall->bpf_filter.family;
        event->type = syscall->bpf_filter.type;
        event->protocol = syscall->bpf_filter.protocol;
        event->prog_len = syscall->bpf_filter.prog_len;

        fill_process_context(&event->process);

        // filter event
        if (filter_out(EVENT_BPF_FILTER, &event)) {
            return 0;
        }

        // send event
        int perf_ret;
        send_event_ptr(ctx, EVENT_BPF_FILTER, event);
    }
    return 0;
}

SYSCALL_KRETPROBE(setsockopt) {
    return sys_setsockopt_ret(ctx, (int)PT_REGS_RC(ctx));
}

SEC("tracepoint/handle_sys_setsockopt_exit")
int tracepoint_handle_sys_setsockopt_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    return sys_setsockopt_ret(args, args->ret);
}

SEC("kprobe/sk_attach_filter")
int BPF_KPROBE(kprobe_sk_attach_filter, struct sock_fprog *fprog, struct sock *sk) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_BPF_FILTER);
    if (!syscall) {
        return 0;
    }

    BPF_CORE_READ_INTO(&syscall->bpf_filter.family, sk, __sk_common.skc_family);
    BPF_CORE_READ_INTO(&syscall->bpf_filter.type, sk, sk_type);
    BPF_CORE_READ_INTO(&syscall->bpf_filter.protocol, sk, sk_protocol);
    BPF_CORE_READ_INTO(&syscall->bpf_filter.prog_len, fprog, len);
    return 0;
}

SEC("kprobe/sk_detach_filter")
int BPF_KPROBE(kprobe_sk_detach_filter, struct sock *sk) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_BPF_FILTER);
    if (!syscall) {
        return 0;
    }

    BPF_CORE_READ_INTO(&syscall->bpf_filter.family, sk, __sk_common.skc_family);
    BPF_CORE_READ_INTO(&syscall->bpf_filter.type, sk, sk_type);
    BPF_CORE_READ_INTO(&syscall->bpf_filter.protocol, sk, sk_protocol);
    return 0;
}

#endif
