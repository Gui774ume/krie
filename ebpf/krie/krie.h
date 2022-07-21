/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KRIE_H_
#define _KRIE_H_

SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(kprobe_vfs_mkdir, struct user_namespace *mnt_userns) {
    bpf_printk("vfs_mkdir\n");
    return 0;
};

SYSCALL_KPROBE2(mkdir, const char*, filename, umode_t, mode) {
    bpf_printk("mkdir: %s\n", filename);

    struct syscall_cache_t hello = {
        .type = EVENT_MKDIR,
    };
    cache_syscall(&hello);

    return 0;
};

SYSCALL_KRETPROBE(mkdir) {
    bpf_printk("mkdir ret\n");
    return 0;
};

SEC("tracepoint/handle_sys_mkdir_exit")
int tracepoint_handle_sys_mkdir_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    bpf_printk("mkdir exit from tracepoint\n");
    pop_syscall(EVENT_MKDIR);
    return 0;
}

#endif