/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KERNEL_SYMBOLS_H_
#define _KERNEL_SYMBOLS_H_

#define KALLSYMS_SYS_CALL_TABLE      0
#define KALLSYMS_X32_SYS_CALL_TABLE  1
#define KALLSYMS_IA32_SYS_CALL_TABLE 2
#define KALLSYMS_STEXT               3
#define KALLSYMS_ETEXT               4

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 5);
} kallsyms SEC(".maps");

static __attribute__((always_inline)) u64 *get_kallsyms_addr(u32 entry) {
    u64 *addr = bpf_map_lookup_elem(&kallsyms, &entry);
    if (addr != NULL) {
        return (void*)*addr;
    }
    return 0;
};

#endif