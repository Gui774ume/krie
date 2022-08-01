/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KERNEL_MODULE_H_
#define _KERNEL_MODULE_H_

struct init_module_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u32 loaded_from_memory;
    u32 padding;
    char name[MODULE_NAME_LEN];
};

memory_factory(init_module_event)

int __attribute__((always_inline)) trace_init_module(void *ctx, u32 loaded_from_memory) {
    struct syscall_cache_t syscall = {
        .type = EVENT_INIT_MODULE,
        .init_module = {
            .loaded_from_memory = loaded_from_memory,
        },
    };

    cache_syscall(&syscall);

    // create process context for KRIE detection
    struct init_module_event_t *event = new_init_module_event();
    if (event == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(&event->process);

    // we're about to allow this call to go through, double check with KRIE
    u32 action = krie_run_event_check(ctx, &event->process, &syscall.type);

    // pop cache if need be
    if (action > KRIE_ACTION_LOG) {
        pop_syscall(EVENT_INIT_MODULE);
    }

    return krie_syscall_kprobe_enforce_policy(ctx, &event->process, action);
};

SYSCALL_KPROBE0(init_module) {
    return trace_init_module(ctx, 1);
};

SYSCALL_KPROBE0(finit_module) {
    return trace_init_module(ctx, 0);
};

int __attribute__((always_inline)) trace_module(void *ctx, struct module *mod) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_INIT_MODULE);
    if (!syscall) {
        return 0;
    }

    BPF_CORE_READ_INTO(&syscall->init_module.name, mod, name);

    // create process context for KRIE detection
    struct init_module_event_t *event = new_init_module_event();
    if (event == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(&event->process);

    // we're about to allow this call to go through, double check with KRIE
    u32 action = krie_run_event_check(ctx, &event->process, &syscall->type);
    return krie_kprobe_enforce_policy(ctx, &event->process, action);
};

SEC("kprobe/do_init_module")
int BPF_KPROBE(kprobe_do_init_module, struct module *mod) {
    return trace_module(ctx, mod);
};

SEC("kprobe/module_put")
int BPF_KPROBE(kprobe_module_put, struct module *mod) {
    return trace_module(ctx, mod);
};

__attribute__((always_inline)) struct process_context_t *trace_init_module_ret(void *ctx, int retval, u32 *action) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_INIT_MODULE);
    if (!syscall) {
        return 0;
    }

    struct init_module_event_t *event = new_init_module_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.type = EVENT_INIT_MODULE;
    event->event.retval = retval;
    bpf_probe_read(&event->loaded_from_memory, sizeof(event->loaded_from_memory), &syscall->init_module.loaded_from_memory);
    bpf_probe_read_str(&event->name[0], sizeof(event->name), &syscall->init_module.name[0]);

    fill_process_context(&event->process);

    // filter krie runtime
    if (filter_krie_runtime()) {
        return 0;
    }

    // run KRIE detections
    event->event.action = krie_run_event_check(ctx, &event->process, &event->event.type);
    *action = event->event.action;

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return &event->process;
};

SYSCALL_KRETPROBE(init_module) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = trace_init_module_ret(ctx, (int)PT_REGS_RC(ctx), &action);
    if (process_ctx == NULL) {
        return 0;
    }

    return krie_syscall_kprobe_enforce_policy(ctx, process_ctx, action);
};

SEC("tracepoint/handle_sys_init_module_exit")
int tracepoint_handle_sys_init_module_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = trace_init_module_ret(args, (int)args->ret, &action);
    if (process_ctx == NULL) {
        return 0;
    }

    return krie_tp_enforce_policy(args, process_ctx, action);
};

SYSCALL_KRETPROBE(finit_module) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = trace_init_module_ret(ctx, (int)PT_REGS_RC(ctx), &action);
    if (process_ctx == NULL) {
        return 0;
    }

    return krie_syscall_kprobe_enforce_policy(ctx, process_ctx, action);
};

SEC("tracepoint/handle_sys_finit_module_exit")
int tracepoint_handle_sys_finit_module_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = trace_init_module_ret(args, (int)args->ret, &action);
    if (process_ctx == NULL) {
        return 0;
    }

    return krie_tp_enforce_policy(args, process_ctx, action);
};

struct delete_module_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    char name[MODULE_NAME_LEN];
};

memory_factory(delete_module_event)

SYSCALL_KPROBE1(delete_module, char *, name_user) {
    struct syscall_cache_t syscall = {
        .type = EVENT_DELETE_MODULE,
        .delete_module = {
            .name = name_user,
        },
    };

    cache_syscall(&syscall);

    // create process context for KRIE detection
    struct delete_module_event_t *event = new_delete_module_event();
    if (event == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(&event->process);

    // we're about to allow this call to go through, double check with KRIE
    u32 action = krie_run_event_check(ctx, &event->process, &syscall.type);

    // pop cache if need be
    if (action > KRIE_ACTION_LOG) {
        pop_syscall(EVENT_DELETE_MODULE);
    }

    return krie_syscall_kprobe_enforce_policy(ctx, &event->process, action);
};

__attribute__((always_inline)) struct process_context_t *trace_delete_module_ret(void *ctx, int retval, u32 *action) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_DELETE_MODULE);
    if (!syscall) {
        return 0;
    }

    struct delete_module_event_t *event = new_delete_module_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.type = EVENT_DELETE_MODULE;
    event->event.retval = retval;
    bpf_probe_read_str(&event->name[0], sizeof(event->name), (void *)syscall->delete_module.name);
    fill_process_context(&event->process);

    // filter krie runtime
    if (filter_krie_runtime()) {
        return 0;
    }

    // run KRIE detections
    event->event.action = krie_run_event_check(ctx, &event->process, &event->event.type);
    *action = event->event.action;

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return &event->process;
};

SYSCALL_KRETPROBE(delete_module) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = trace_delete_module_ret(ctx, (int)PT_REGS_RC(ctx), &action);
    if (process_ctx == NULL) {
        return 0;
    }

    return krie_syscall_kprobe_enforce_policy(ctx, process_ctx, action);
};

SEC("tracepoint/handle_sys_delete_module_exit")
int tracepoint_handle_sys_delete_module_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = trace_delete_module_ret(args, (int)args->ret, &action);
    if (process_ctx == NULL) {
        return 0;
    }

    return krie_tp_enforce_policy(args, process_ctx, action);
};

#endif
