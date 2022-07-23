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
    return 0;
}

int __attribute__((always_inline)) sys_ptrace_ret(void *ctx, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_PTRACE);
    if (!syscall) {
        return 0;
    }

    struct ptrace_event_t *event = new_ptrace_event();
    if (event == NULL) {
        // ignore, should not happen
        return 0;
    }
    event->event.retval = retval;
    event->pid = syscall->ptrace.pid;
    event->request = syscall->ptrace.request;
    event->addr = syscall->ptrace.addr;

    fill_process_context(&event->process);

    int perf_ret;
    send_event_ptr(ctx, EVENT_PTRACE, event);
    return 0;
}

SYSCALL_KRETPROBE(ptrace) {
    return sys_ptrace_ret(ctx, (int)PT_REGS_RC(ctx));
}

SEC("tracepoint/handle_sys_ptrace_exit")
int tracepoint_handle_sys_ptrace_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    return sys_ptrace_ret(args, (int)args->ret);
}

#endif