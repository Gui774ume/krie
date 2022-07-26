/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _FILTER_H_
#define _FILTER_H_

int __attribute__((always_inline)) filter_out(u32 event_type, void *event) {
    // filter pid
    u32 id = bpf_get_current_pid_tgid() >> 32;
    if (id == (u32)get_krie_pid()) {
        return 1;
    }

    return 0;
};

#endif