/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SYSCALL_CACHE_H_
#define _SYSCALL_CACHE_H_

struct syscall_cache_t {
    u64 type;

    union {
        struct {
            char name[MODULE_NAME_LEN];
            u32 loaded_from_memory;
        } init_module;

        struct {
            char *name;
        } delete_module;

        struct {
            int cmd;
            u32 map_id;
            u32 prog_id;
            int retval;
            u64 helpers[3];
            union bpf_attr_def *attr;
        } bpf;

        struct {
            int bpf_filter_cmd;
            u16 family;
            u16 type;
            u16 protocol;
            u16 prog_len;
        } bpf_filter;

        struct {
            u32 request;
            u32 pid;
            u64 addr;
        } ptrace;
    };
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, struct syscall_cache_t);
	__uint(max_entries, 1024);
} syscalls SEC(".maps");

void __attribute__((always_inline)) cache_syscall(struct syscall_cache_t *syscall) {
    u64 key = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&syscalls, &key, syscall, BPF_ANY);
}

struct syscall_cache_t *__attribute__((always_inline)) peek_syscall(u64 type) {
    u64 key = bpf_get_current_pid_tgid();
    struct syscall_cache_t *syscall = (struct syscall_cache_t *)bpf_map_lookup_elem(&syscalls, &key);
    if (!syscall) {
        return NULL;
    }
    if (!type || syscall->type == type) {
        return syscall;
    }
    return NULL;
}

struct syscall_cache_t *__attribute__((always_inline)) pop_syscall(u64 type) {
    u64 key = bpf_get_current_pid_tgid();
    struct syscall_cache_t *syscall = (struct syscall_cache_t *)bpf_map_lookup_elem(&syscalls, &key);
    if (!syscall) {
        return NULL;
    }
    if (!type || syscall->type == type) {
        bpf_map_delete_elem(&syscalls, &key);
        return syscall;
    }
    return NULL;
}

#endif
