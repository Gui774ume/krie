/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _TASK_CHECK_H_
#define _TASK_CHECK_H_

struct register_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u64 sp;
    u64 ip;
    u64 fp;
    u32 hookpoint;
    u32 register_type;
};

memory_factory(register_event)

#define KERNEL_ADDR_START 0xffff800000000000

#define IP_REGISTER 0
#define SP_REGISTER 1
#define FP_REGISTER 2

__attribute__((always_inline)) u32 check_registers(struct pt_regs *ctx, struct process_context_t *process_ctx, u32 hookpoint) {
    // fetch event policy
    u32 event_type = EVENT_REGISTER_CHECK;
    fetch_policy_or_log(event_type)

    // prepare new event
    int perf_ret;
    struct register_event_t *event = new_register_event();
    if (event == NULL) {
        // should never happen, ignore
        return KRIE_ACTION_NOP;
    }
    event->event.type = EVENT_REGISTER_CHECK;
    event->event.action = policy->action;
    event->hookpoint = hookpoint;
    copy_process_ctx(&event->process, process_ctx);

    // check if IP is in kernel space
    event->sp = PT_REGS_SP(ctx);
    event->ip = PT_REGS_IP(ctx);
    event->fp = PT_REGS_FP(ctx);
    if (event->ip < KERNEL_ADDR_START || event->sp < KERNEL_ADDR_START || event->fp < KERNEL_ADDR_START) {
        // send event
        send_event_ptr(ctx, event->event.type, event);
        return policy->action;
    }

    return KRIE_ACTION_NOP;
};

__attribute__((always_inline)) u32 run_task_check(struct pt_regs *ctx, struct process_context_t *process_ctx, u32 hookpoint) {
    return check_registers(ctx, process_ctx, hookpoint);
};

#endif