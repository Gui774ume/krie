/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KRIE_H_
#define _KRIE_H_

#define KRIE_NO_CHECK                  0 << 0
#define KRIE_SYSCALL_TABLES_CHECK      1 << 0
#define KRIE_SYSCALL_CHECK             1 << 1
#define KRIE_EVENT_CHECK               1 << 2
#define KRIE_KERNEL_PARAMETER          1 << 3
#define KRIE_PERIODIC_KERNEL_PARAMETER 1 << 4
#define KRIE_CHECK_COUNT 4

#include "policy.h"
#include "kernel_symbols.h"
#include "syscall_check.h"
#include "kill_switch.h"
#include "event_check.h"
#include "kernel_parameter.h"

static __attribute__((always_inline)) u8 is_set(u64 input, u64 flag) {
    return (input & flag) == flag;
};

static __attribute__((always_inline)) u32 krie_run_detections(void *ctx, u64 flag, struct process_context_t *process_ctx, void *data) {
    struct policy_t policy = {
        .action = KRIE_ACTION_NOP,
    };
    u32 check_action = KRIE_ACTION_NOP;

    if (is_set(flag, KRIE_SYSCALL_TABLES_CHECK)) {
        check_action = run_syscall_table_check(ctx);
        if (policy.action < check_action) {
            policy.action = check_action;
        }
    }

    if (is_set(flag, KRIE_SYSCALL_CHECK)) {
        check_action = run_syscall_check(ctx, process_ctx, data);
        if (policy.action < check_action) {
            policy.action = check_action;
        }
    }

    if (is_set(flag, KRIE_EVENT_CHECK)) {
        check_action = run_event_check(ctx, process_ctx, data);
        if (policy.action < check_action) {
            policy.action = check_action;
        }
    }

    if (is_set(flag, KRIE_KERNEL_PARAMETER) || is_set(flag, KRIE_PERIODIC_KERNEL_PARAMETER)) {
        check_action = run_kernel_parameter_check(ctx, process_ctx, is_set(flag, KRIE_PERIODIC_KERNEL_PARAMETER));
        if (policy.action < check_action) {
            policy.action = check_action;
        }
    }

    // set process kill switch
    if (policy.action == KRIE_ACTION_KILL) {
        set_process_kill_switch(&policy, process_ctx);
    }

    // set global kill switch
    if (policy.action == KRIE_ACTION_PARANOID) {
        set_global_kill_switch(&policy);
    }

    // check task kill switch
    struct policy_t *kill_switch = get_process_kill_switch(process_ctx);
    if (kill_switch) {
        if (policy.action < kill_switch->action) {
            policy.action = kill_switch->action;
        }
    }

    // check global kill switch
    kill_switch = get_global_kill_switch();
    if (kill_switch) {
        if (policy.action < kill_switch->action) {
            policy.action = kill_switch->action;
        }
    }
    return policy.action;
};

#endif