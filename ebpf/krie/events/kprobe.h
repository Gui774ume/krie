/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KPROBE_H_
#define _KPROBE_H_

#define KPROBE_TYPE 1
#define KRETPROBE_TYPE 2

#define REGISTER_KPROBE 1
#define UNREGISTER_KPROBE 2
#define REGISTER_KRETPROBE 3
#define UNREGISTER_KRETPROBE 4
#define ENABLE_KPROBE 5
#define DISABLE_KPROBE 6
#define DISARM_ALL_KPROBE 7

struct kprobe_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u64 addr;
    u32 cmd;
    u32 kprobe_type;
    char symbol[SYMBOL_NAME_LENGTH];
};

memory_factory(kprobe_event)

int __attribute__((always_inline)) cache_kprobe(struct kprobe *p) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_KPROBE);
    if (syscall == NULL) {
        struct syscall_cache_t new_syscall = {
            .type = EVENT_KPROBE,
            .kprobe = {
                .kprobe_type = KPROBE_TYPE,
            },
        };
        cache_syscall(&new_syscall);
        syscall = peek_syscall(EVENT_KPROBE);
    }
    if (syscall == NULL) {
        // should neven happen, ignore
        return 0;
    }

    syscall->kprobe.p = p;
    return 0;
}

SEC("kprobe/register_kprobe")
int BPF_KPROBE(kprobe_register_kprobe, struct kprobe *p) {
    return cache_kprobe(p);
};

SEC("kretprobe/register_kprobe")
int BPF_KRETPROBE(kretprobe_register_kprobe, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->cmd = REGISTER_KPROBE;
    event->kprobe_type = syscall->kprobe.kprobe_type;

    struct kprobe *p = syscall->kprobe.p;
    BPF_CORE_READ_INTO(&event->addr, p, addr);
    char *symbol = NULL;
    BPF_CORE_READ_INTO(&symbol, p, symbol_name);
    bpf_probe_read_str(&event->symbol, sizeof(event->symbol), symbol);

    fill_process_context(&event->process);

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
};

SEC("kprobe/__unregister_kprobe_top")
int BPF_KPROBE(kprobe___unregister_kprobe_top, struct kprobe *p) {
    return cache_kprobe(p);
};

SEC("kretprobe/__unregister_kprobe_top")
int BPF_KRETPROBE(kretprobe___unregister_kprobe_top, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->cmd = UNREGISTER_KPROBE;
    event->kprobe_type = syscall->kprobe.kprobe_type;

    struct kprobe *p = syscall->kprobe.p;
    BPF_CORE_READ_INTO(&event->addr, p, addr);
    char *symbol = NULL;
    BPF_CORE_READ_INTO(&symbol, p, symbol_name);
    bpf_probe_read_str(&event->symbol, sizeof(event->symbol), symbol);

    fill_process_context(&event->process);

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
};

SEC("kprobe/enable_kprobe")
int BPF_KPROBE(kprobe_enable_kprobe, struct kprobe *p) {
    return cache_kprobe(p);
};

SEC("kretprobe/enable_kprobe")
int BPF_KRETPROBE(kretprobe_enable_kprobe, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->cmd = ENABLE_KPROBE;
    event->kprobe_type = syscall->kprobe.kprobe_type;

    struct kprobe *p = syscall->kprobe.p;
    BPF_CORE_READ_INTO(&event->addr, p, addr);
    char *symbol = NULL;
    BPF_CORE_READ_INTO(&symbol, p, symbol_name);
    bpf_probe_read_str(&event->symbol, sizeof(event->symbol), symbol);

    fill_process_context(&event->process);

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
};

SEC("kprobe/disable_kprobe")
int BPF_KPROBE(kprobe_disable_kprobe, struct kprobe *p) {
    return cache_kprobe(p);
};

SEC("kretprobe/disable_kprobe")
int BPF_KRETPROBE(kretprobe_disable_kprobe, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->cmd = DISABLE_KPROBE;
    event->kprobe_type = syscall->kprobe.kprobe_type;

    struct kprobe *p = syscall->kprobe.p;
    BPF_CORE_READ_INTO(&event->addr, p, addr);
    char *symbol = NULL;
    BPF_CORE_READ_INTO(&symbol, p, symbol_name);
    bpf_probe_read_str(&event->symbol, sizeof(event->symbol), symbol);

    fill_process_context(&event->process);

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
};

SEC("kprobe/register_kretprobe")
int BPF_KPROBE(kprobe_register_kretprobe, struct kretprobe *kretp) {
    struct syscall_cache_t syscall = {
        .type = EVENT_KPROBE,
        .kprobe = {
            .kprobe_type = KRETPROBE_TYPE,
        },
    };

    cache_syscall(&syscall);
    return 0;
};

SEC("kprobe/unregister_kretprobe")
int BPF_KPROBE(kprobe_unregister_kretprobe, struct kretprobe *rp) {
    struct syscall_cache_t syscall = {
        .type = EVENT_KPROBE,
        .kprobe = {
            .kprobe_type = KRETPROBE_TYPE,
        },
    };

    cache_syscall(&syscall);
    return 0;
}

#endif