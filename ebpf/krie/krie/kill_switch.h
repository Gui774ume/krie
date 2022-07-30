/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KILL_SWITCH_H_
#define _KILL_SWITCH_H_

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct policy_t);
	__uint(max_entries, 1);
} global_kill_switch SEC(".maps");

__attribute__((always_inline)) struct policy_t *get_global_kill_switch() {
    u32 key = 0;
    return bpf_map_lookup_elem(&global_kill_switch, &key);
};

__attribute__((always_inline)) u64 set_global_kill_switch(struct policy_t *policy) {
    u32 key = 0;
    return bpf_map_update_elem(&global_kill_switch, &key, policy, BPF_ANY);
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct policy_t);
	__uint(max_entries, 8192);
} process_kill_switch SEC(".maps");

__attribute__((always_inline)) struct policy_t *get_process_kill_switch(struct process_context_t *process_ctx) {
    u32 key = process_ctx->pid;
    return bpf_map_lookup_elem(&process_kill_switch, &key);
};

__attribute__((always_inline)) u64 set_process_kill_switch(struct policy_t *policy, struct process_context_t *process_ctx) {
    u32 key = process_ctx->pid;
    return bpf_map_update_elem(&global_kill_switch, &key, policy, BPF_ANY);
};

#endif