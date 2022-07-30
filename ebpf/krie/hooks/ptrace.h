/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PTRACE_H_
#define _PTRACE_H_

struct ptrace_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u64 addr;
    u32 request;
    u32 pid;
};

memory_factory(ptrace_event)

SYSCALL_KPROBE3(ptrace, u32, request, pid_t, pid, void *, addr) {
    struct syscall_cache_t syscall = {
        .type = EVENT_PTRACE,
        .ptrace = {
            .request = request,
            .pid = pid,
            .addr = (u64)addr,
        }
    };

    cache_syscall(&syscall);

    // create process context for KRIE detection
    struct ptrace_event_t *event = new_ptrace_event();
    if (event == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(&event->process);

    // we're about to allow this call to go through, double check with KRIE
    u32 action = krie_run_detections(ctx, KRIE_EVENT_CHECK, &event->process, &syscall.type);

    // pop cache if need be
    if (action > KRIE_ACTION_LOG) {
        pop_syscall(EVENT_PTRACE);
    }

    return krie_syscall_kprobe_enforce_policy(ctx, &event->process, action);
}

__attribute__((always_inline)) struct process_context_t *sys_ptrace_ret(void *ctx, int retval, u32 *action) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_PTRACE);
    if (!syscall) {
        return 0;
    }

    struct ptrace_event_t *event = new_ptrace_event();
    if (event == NULL) {
        // ignore, should not happen
        return 0;
    }
    event->event.type = EVENT_PTRACE;
    event->event.retval = retval;
    event->pid = syscall->ptrace.pid;
    event->request = syscall->ptrace.request;
    event->addr = syscall->ptrace.addr;

    fill_process_context(&event->process);

    // filter krie runtime
    if (filter_krie_runtime()) {
        return 0;
    }

    // run KRIE detections
    event->event.action = krie_run_detections(ctx, KRIE_EVENT_CHECK, &event->process, &event->event.type);
    *action = event->event.action;

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return &event->process;
}

SYSCALL_KRETPROBE(ptrace) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = sys_ptrace_ret(ctx, (int)PT_REGS_RC(ctx), &action);
    if (process_ctx == NULL) {
        return 0;
    }

    return krie_syscall_kprobe_enforce_policy(ctx, process_ctx, action);
}

SEC("tracepoint/handle_sys_ptrace_exit")
int tracepoint_handle_sys_ptrace_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = sys_ptrace_ret(args, (int)args->ret, &action);
    if (process_ctx == NULL) {
        return 0;
    }

    return krie_tp_enforce_policy(args, process_ctx, action);
}

#endif