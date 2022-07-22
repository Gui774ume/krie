/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#define CGROUP_MAX_LENGTH 72
#define TASK_COMM_LEN 16
#define MODULE_NAME_LEN 56

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

static __attribute__((always_inline)) u64 get_raw_syscall_tracepoint_fallback() {
    u64 raw_syscall_tracepoint_fallback;
    LOAD_CONSTANT("raw_syscall_tracepoint_fallback", raw_syscall_tracepoint_fallback);
    return raw_syscall_tracepoint_fallback;
}

#endif
