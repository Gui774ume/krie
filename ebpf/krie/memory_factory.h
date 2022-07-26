/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _MEMORY_FACTORY_H_
#define _MEMORY_FACTORY_H_

#define STRUCT_ZERO_KEY 0
#define STRUCT_WORKING_KEY 1

#define memory_factory(NAME)                                                                                           \
                                                                                                                       \
    struct {                                                                                                           \
	    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                                       \
	    __type(key, u32);                                                                                              \
	    __type(value, struct NAME##_t);                                                                                \
	    __uint(max_entries, 2);                                                                                        \
    } NAME##_gen SEC(".maps");                                                                                         \
                                                                                                                       \
    __attribute__((always_inline)) struct NAME##_t *new_##NAME() {                                                     \
        u32 key = STRUCT_ZERO_KEY;                                                                                     \
        struct NAME##_t *zero = bpf_map_lookup_elem(&NAME##_gen, &key);                                                \
        if (zero == NULL) {                                                                                            \
            return NULL;                                                                                               \
        }                                                                                                              \
        key = STRUCT_WORKING_KEY;                                                                                      \
        struct NAME##_t *elem = bpf_map_lookup_elem(&NAME##_gen, &key);                                                \
        if (elem == NULL) {                                                                                            \
            return NULL;                                                                                               \
        }                                                                                                              \
                                                                                                                       \
        bpf_probe_read_kernel(elem, sizeof(struct NAME##_t), zero);                                                    \
        return elem;                                                                                                   \
    };                                                                                                                 \

#endif