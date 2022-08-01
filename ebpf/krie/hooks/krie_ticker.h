/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KRIE_TICKER_H_
#define _KRIE_TICKER_H_

SEC("perf_event/syscall_table_ticker")
int perf_event_syscall_table_ticker(struct bpf_perf_event_data *ctx) {
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen, ignore
        return 0;
    }
    fill_process_context(process_ctx);

    u32 action = krie_run_syscall_tables_detection(ctx, process_ctx);
    return krie_perf_enforce_policy(ctx, process_ctx, action);
};

SEC("perf_event/kernel_parameter_ticker")
int perf_event_kernel_parameter_ticker(struct bpf_perf_event_data *ctx) {
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen, ignore
        return 0;
    }
    fill_process_context(process_ctx);

    u32 action = krie_run_kernel_parameter_detection(ctx, process_ctx);
    return krie_perf_enforce_policy(ctx, process_ctx, action);
};

#endif