/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _POLICY_H_
#define _POLICY_H_

#define KRIE_ACTION_NOP      0
#define KRIE_ACTION_LOG      1
#define KRIE_ACTION_BLOCK    2
#define KRIE_ACTION_KILL     3
#define KRIE_ACTION_PARANOID 4

struct policy_t {
    u32 action;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct policy_t);
	__uint(max_entries, EVENT_MAX);
} policies SEC(".maps");

__attribute__((always_inline)) struct policy_t *get_policy(u32 event_type) {
    return bpf_map_lookup_elem(&policies, &event_type);
};

// program types
#define KPROBE_PROG        1
#define TRACEPOINT_PROG    2
#define LSM_PROG           3
#define PERF_EVENT_PROG    4
#define CGROUP_SYSCTL_PROG 5

// hook type
#define SYMBOL_HOOK  0
#define SYSCALL_HOOK 1

__attribute__((always_inline)) int enforce_policy(void *ctx, struct process_context_t *process_ctx, u32 action, u32 program_type, u32 hook_type) {
    // make sure we skip any kind of enforcement for the KRIE runtime
    if (filter_krie_runtime_with_pid(process_ctx->pid)) {
        action = KRIE_ACTION_NOP;
    }

    switch (action) {
        case KRIE_ACTION_NOP:
        case KRIE_ACTION_LOG:
            // handled in each program
            if (program_type == CGROUP_SYSCTL_PROG) {
                return 1; // see SYSCTL_OK in hooks/sysctl.h
            }
            break;
        case KRIE_ACTION_BLOCK:
            if (program_type == KPROBE_PROG && hook_type == SYSCALL_HOOK) {
                if (get_krie_override_return()) {
                    bpf_override_return(ctx, -1); // EPERM
                }
            } else if (program_type == LSM_PROG) {
                return -1; // EPERM
            } else if (program_type == CGROUP_SYSCTL_PROG) {
                return 0; // see SYSCTL_SHOT in hooks/sysctl.h
            }
            break;
        case KRIE_ACTION_KILL:
        case KRIE_ACTION_PARANOID:
            if (program_type != CGROUP_SYSCTL_PROG) {
                if (get_krie_send_signal()) {
                    bpf_send_signal(9); // SIGKILL
                }
            }
            if (program_type == KPROBE_PROG && hook_type == SYSCALL_HOOK) {
                if (get_krie_override_return()) {
                    bpf_override_return(ctx, -1); // EPERM
                }
            }
            if (program_type == LSM_PROG) {
                return -1; // EPERM
            } else if (program_type == CGROUP_SYSCTL_PROG) {
                return 0; // see SYSCTL_SHOT in hooks/sysctl.h
            }
            break;
    }
    return 0;
};

__attribute__((always_inline)) int krie_tp_enforce_policy(void *ctx, struct process_context_t *process_ctx, u32 action) {
    return enforce_policy(ctx, process_ctx, action, TRACEPOINT_PROG, SYMBOL_HOOK);
};

__attribute__((always_inline)) int krie_perf_enforce_policy(void *ctx, struct process_context_t *process_ctx, u32 action) {
    return enforce_policy(ctx, process_ctx, action, PERF_EVENT_PROG, SYMBOL_HOOK);
};

__attribute__((always_inline)) int krie_cgroup_sysctl_enforce_policy(void *ctx, struct process_context_t *process_ctx, u32 action) {
    return enforce_policy(ctx, process_ctx, action, CGROUP_SYSCTL_PROG, SYMBOL_HOOK);
};

__attribute__((always_inline)) int krie_syscall_kprobe_enforce_policy(void *ctx, struct process_context_t *process_ctx, u32 action) {
    return enforce_policy(ctx, process_ctx, action, KPROBE_PROG, SYSCALL_HOOK);
};

__attribute__((always_inline)) int krie_kprobe_enforce_policy(void *ctx, struct process_context_t *process_ctx, u32 action) {
    return enforce_policy(ctx, process_ctx, action, KPROBE_PROG, SYMBOL_HOOK);
};

__attribute__((always_inline)) int krie_lsm_enforce_policy(void *ctx, struct process_context_t *process_ctx, u32 action) {
    return enforce_policy(ctx, process_ctx, action, LSM_PROG, SYMBOL_HOOK);
};

#define fetch_policy_or_block(check)                                                                                   \
    struct policy_t new_policy = {};                                                                                   \
    struct policy_t *policy = get_policy(check);                                                                       \
    if (policy == NULL) {                                                                                              \
        new_policy.action = KRIE_ACTION_BLOCK;                                                                         \
        policy = &new_policy;                                                                                          \
    }                                                                                                                  \
    if (policy == NULL) {                                                                                              \
        return KRIE_ACTION_NOP;                                                                                        \
    }                                                                                                                  \
    if (policy->action == KRIE_ACTION_NOP) {                                                                           \
        return KRIE_ACTION_NOP;                                                                                        \
    }                                                                                                                  \

#define fetch_policy_or_log(check)                                                                                     \
    struct policy_t new_policy = {};                                                                                   \
    struct policy_t *policy = get_policy(check);                                                                       \
    if (policy == NULL) {                                                                                              \
        new_policy.action = KRIE_ACTION_LOG;                                                                           \
        policy = &new_policy;                                                                                          \
    }                                                                                                                  \
    if (policy == NULL) {                                                                                              \
        return KRIE_ACTION_NOP;                                                                                        \
    }                                                                                                                  \
    if (policy->action == KRIE_ACTION_NOP) {                                                                           \
        return KRIE_ACTION_NOP;                                                                                        \
    }                                                                                                                  \

#endif