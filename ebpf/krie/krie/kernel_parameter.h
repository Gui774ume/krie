/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KERNEL_PARAMETER_H_
#define _KERNEL_PARAMETER_H_

struct kernel_parameter_t {
    u64 addr;
    u64 expected_value;
    u64 last_sent;
    u64 size;
};

struct kernel_parameter_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u64 addr;
    u64 expected_value;
    u64 actual_value;
};

memory_factory(kernel_parameter_event)

#define KERNEL_PARAMETER_MAX 50

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct kernel_parameter_t);
	__uint(max_entries, KERNEL_PARAMETER_MAX);
} kernel_parameters SEC(".maps");

__attribute__((always_inline)) u32 run_kernel_parameter_check(void *ctx, struct process_context_t *process_ctx, u8 is_periodic) {
    u32 kernel_parameter_key = 0;
    struct kernel_parameter_t *param = NULL;
    bool triggered = 0;
    int perf_ret = 0;
    u64 now = bpf_ktime_get_ns();
    u64 threshold = now - get_kernel_parameter_ticker();
    struct kernel_parameter_event_t *event = new_kernel_parameter_event();
    if (event == NULL) {
        // should never happen, ignore
        return KRIE_ACTION_NOP;
    }

    event->event.type = EVENT_KERNEL_PARAMETER;
    if (is_periodic) {
        event->event.type = EVENT_PERIODIC_KERNEL_PARAMETER;
    }
    copy_process_ctx(&event->process, process_ctx);
    fetch_policy_or_block(event->event.type)
    event->event.action = policy->action;

    #pragma unroll
    for(int i = 0; i < KERNEL_PARAMETER_MAX; i++) {
        if (i >= get_kernel_parameter_count()){
            goto out;
        }
        kernel_parameter_key = i;
        param = bpf_map_lookup_elem(&kernel_parameters, &kernel_parameter_key);
        if (param == NULL) {
            goto out;
        }
        if (param->addr == 0) {
            goto out;
        }
        bpf_probe_read_kernel(&event->actual_value, (param->size & 7), (void *)param->addr);

        if (param->expected_value != event->actual_value && param->last_sent < threshold) {
            triggered = 1;
            event->addr = param->addr;
            event->expected_value = param->expected_value;
            send_event_ptr(ctx, event->event.type, event);
            if (perf_ret == 0) {
                param->last_sent = now;
            }
        }
    }

out:
    if (triggered) {
        return policy->action;
    }
    return KRIE_ACTION_NOP;
};

#endif