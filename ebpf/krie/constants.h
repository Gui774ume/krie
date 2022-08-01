/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#define CGROUP_MAX_LENGTH 128
#define TASK_COMM_LEN 16
#define MODULE_NAME_LEN 56
#define BPF_OBJ_NAME_LEN 16
#define BPF_TAG_SIZE 8
#define SYMBOL_NAME_LENGTH 64

#include "hooks/bpf_const.h"

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

__attribute__((always_inline)) u64 get_raw_syscall_tracepoint_fallback() {
    u64 raw_syscall_tracepoint_fallback;
    LOAD_CONSTANT("raw_syscall_tracepoint_fallback", raw_syscall_tracepoint_fallback);
    return raw_syscall_tracepoint_fallback;
};

__attribute__((always_inline)) u64 get_check_helper_call_input() {
    u64 input;
    LOAD_CONSTANT("check_helper_call_input", input);
    return input;
};

__attribute__((always_inline)) u64 get_krie_pid() {
    u64 krie_pid;
    LOAD_CONSTANT("krie_pid", krie_pid);
    return krie_pid;
};

__attribute__((always_inline)) u64 get_krie_send_signal() {
    u64 krie_send_signal;
    LOAD_CONSTANT("krie_send_signal", krie_send_signal);
    return krie_send_signal;
};

__attribute__((always_inline)) u64 get_krie_override_return() {
    u64 krie_override_return;
    LOAD_CONSTANT("krie_override_return", krie_override_return);
    return krie_override_return;
};

__attribute__((always_inline)) u64 get_kernel_parameter_ticker() {
    u64 kernel_parameter_ticker;
    LOAD_CONSTANT("kernel_parameter_ticker", kernel_parameter_ticker);
    return kernel_parameter_ticker;
};

__attribute__((always_inline)) u64 get_kernel_parameter_count() {
    u64 kernel_parameter_count;
    LOAD_CONSTANT("kernel_parameter_count", kernel_parameter_count);
    return kernel_parameter_count;
};

#endif
