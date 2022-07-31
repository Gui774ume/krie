/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KRIE_TIMER_H_
#define _KRIE_TIMER_H_

SEC("perf_event/cpu_clock")
int perf_event_cpu_clock(struct bpf_perf_event_data *ctx)
{
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen, ignore
        return 0;
    }
    fill_process_context(process_ctx);

    u32 action = krie_run_detections(ctx, KRIE_SYSCALL_TABLES_CHECK | KRIE_PERIODIC_KERNEL_PARAMETER, process_ctx, NULL);
    return krie_perf_enforce_policy(ctx, process_ctx, action);
};

#endif