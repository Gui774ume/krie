/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _EVENTS_H_
#define _EVENTS_H_

enum event_type
{
    EVENT_ANY = 0,
    EVENT_INIT_MODULE,
    EVENT_DELETE_MODULE,
    EVENT_BPF,
    EVENT_BPF_FILTER,
    EVENT_PTRACE,
    EVENT_KPROBE,
    EVENT_SYSCTL,

    // KRIE security events
    EVENT_HOOKED_SYSCALL_TABLE,
    EVENT_HOOKED_SYSCALL,
    EVENT_CHECK_EVENT,
    EVENT_KERNEL_PARAMETER,
    EVENT_PERIODIC_KERNEL_PARAMETER,
    EVENT_REGISTER_CHECK,
    EVENT_MAX, // has to be the last one
};

struct kernel_event_t {
    u64 timestamp;
    s64 retval;
    u32 cpu;
    u32 type;
    u32 action;
    u32 padding;
};

struct perf_map_stats_t {
    u64 bytes;
    u64 count;
    u64 lost;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

#define send_event_with_size_ptr_perf(ctx, event_type, kernel_event, kernel_event_size)                                \
    kernel_event->event.type = event_type;                                                                             \
    kernel_event->event.cpu = bpf_get_smp_processor_id();                                                              \
    kernel_event->event.timestamp = bpf_ktime_get_ns();                                                                \
    perf_ret = bpf_perf_event_output(ctx, &events, kernel_event->event.cpu, kernel_event, kernel_event_size);          \

#define send_event_with_size_perf(ctx, event_type, kernel_event, kernel_event_size)                                    \
    kernel_event.event.type = event_type;                                                                              \
    kernel_event.event.cpu = bpf_get_smp_processor_id();                                                               \
    kernel_event.event.timestamp = bpf_ktime_get_ns();                                                                 \
    perf_ret = bpf_perf_event_output(ctx, &events, kernel_event.event.cpu, &kernel_event, kernel_event_size);          \

#define send_event(ctx, event_type, kernel_event)                                                                      \
    u64 size = sizeof(kernel_event);                                                                                   \
    send_event_with_size_perf(ctx, event_type, kernel_event, size)                                                     \

#define send_event_with_size(ctx, event_type, kernel_event, size)                                                      \
    send_event_with_size_perf(ctx, event_type, kernel_event, size)                                                     \

#define send_event_ptr(ctx, event_type, kernel_event)                                                                  \
    u64 size = sizeof(*kernel_event);                                                                                  \
    send_event_with_size_ptr_perf(ctx, event_type, kernel_event, size)                                                 \

#define send_event_with_size_ptr(ctx, event_type, kernel_event, size)                                                  \
    send_event_with_size_ptr_perf(ctx, event_type, kernel_event, size)                                                 \

#endif
