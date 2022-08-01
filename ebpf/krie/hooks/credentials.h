/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CREDENTIALS_H_
#define _CREDENTIALS_H_

SEC("kprobe/prepare_kernel_cred")
int BPF_KPROBE(kprobe_prepare_kernel_cred) {
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen, ignore
        return 0;
    }
    fill_process_context(process_ctx);

    u32 action = run_task_check(ctx, process_ctx, PREPARE_KERNEL_CRED_HOOK);
    return krie_perf_enforce_policy(ctx, process_ctx, action);
};

SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds) {
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen, ignore
        return 0;
    }
    fill_process_context(process_ctx);

    u32 action = run_task_check(ctx, process_ctx, COMMIT_CREDS_HOOK);
    return krie_perf_enforce_policy(ctx, process_ctx, action);
};

#endif