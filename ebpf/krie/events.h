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
    EVENT_MAX, // has to be the last one
};

struct kernel_event_t {
    u64 timestamp;
    s64 retval;
    u32 cpu;
    u32 type;
};

struct perf_map_stats_t {
    u64 bytes;
    u64 count;
    u64 lost;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct perf_map_stats_t);
	__uint(max_entries, EVENT_MAX);
} events_stats SEC(".maps");

#define send_event_with_size_ptr_perf(ctx, event_type, kernel_event, kernel_event_size)                                \
    kernel_event->event.type = event_type;                                                                             \
    kernel_event->event.cpu = bpf_get_smp_processor_id();                                                              \
    kernel_event->event.timestamp = bpf_ktime_get_ns();                                                                \
                                                                                                                       \
    perf_ret = bpf_perf_event_output(ctx, &events, kernel_event->event.cpu, kernel_event, kernel_event_size);          \
                                                                                                                       \
    if (kernel_event->event.type < EVENT_MAX) {                                                                        \
        u64 lookup_type = event_type;                                                                                  \
        struct perf_map_stats_t *stats = bpf_map_lookup_elem(&events_stats, &lookup_type);                             \
        if (stats != NULL) {                                                                                           \
            if (!perf_ret) {                                                                                           \
                __sync_fetch_and_add(&stats->bytes, kernel_event_size + 4);                                            \
                __sync_fetch_and_add(&stats->count, 1);                                                                \
            } else {                                                                                                   \
                __sync_fetch_and_add(&stats->lost, 1);                                                                 \
            }                                                                                                          \
        }                                                                                                              \
    }                                                                                                                  \

#define send_event_with_size_ptr_ringbuf(ctx, event_type, kernel_event, kernel_event_size)                             \
    kernel_event->event.type = event_type;                                                                             \
    kernel_event->event.cpu = bpf_get_smp_processor_id();                                                              \
    kernel_event->event.timestamp = bpf_ktime_get_ns();                                                                \
                                                                                                                       \
    perf_ret = bpf_ringbuf_output(&events, kernel_event, kernel_event_size, 0);                                        \
                                                                                                                       \
    if (kernel_event->event.type < EVENT_MAX) {                                                                        \
        u64 lookup_type = event_type;                                                                                  \
        struct perf_map_stats_t *stats = bpf_map_lookup_elem(&events_stats, &lookup_type);                             \
        if (stats != NULL) {                                                                                           \
            if (!perf_ret) {                                                                                           \
                __sync_fetch_and_add(&stats->bytes, kernel_event_size + 4);                                            \
                __sync_fetch_and_add(&stats->count, 1);                                                                \
            } else {                                                                                                   \
                __sync_fetch_and_add(&stats->lost, 1);                                                                 \
            }                                                                                                          \
        }                                                                                                              \
    }                                                                                                                  \

#define send_event_with_size_perf(ctx, event_type, kernel_event, kernel_event_size)                                    \
    kernel_event.event.type = event_type;                                                                              \
    kernel_event.event.cpu = bpf_get_smp_processor_id();                                                               \
    kernel_event.event.timestamp = bpf_ktime_get_ns();                                                                 \
                                                                                                                       \
    perf_ret = bpf_perf_event_output(ctx, &events, kernel_event.event.cpu, &kernel_event, kernel_event_size);          \
                                                                                                                       \
    if (kernel_event.event.type < EVENT_MAX) {                                                                         \
        struct perf_map_stats_t *stats = bpf_map_lookup_elem(&events_stats, &kernel_event.event.type);                 \
        if (stats != NULL) {                                                                                           \
            if (!perf_ret) {                                                                                           \
                __sync_fetch_and_add(&stats->bytes, kernel_event_size + 4);                                            \
                __sync_fetch_and_add(&stats->count, 1);                                                                \
            } else {                                                                                                   \
                __sync_fetch_and_add(&stats->lost, 1);                                                                 \
            }                                                                                                          \
        }                                                                                                              \
    }                                                                                                                  \

#define send_event_with_size_ringbuf(ctx, event_type, kernel_event, kernel_event_size)                                 \
    kernel_event.event.type = event_type;                                                                              \
    kernel_event.event.cpu = bpf_get_smp_processor_id();                                                               \
    kernel_event.event.timestamp = bpf_ktime_get_ns();                                                                 \
                                                                                                                       \
    perf_ret = bpf_ringbuf_output(&events, &kernel_event, kernel_event_size, 0);                                       \
                                                                                                                       \
    if (kernel_event.event.type < EVENT_MAX) {                                                                         \
        struct perf_map_stats_t *stats = bpf_map_lookup_elem(&events_stats, &kernel_event.event.type);                 \
        if (stats != NULL) {                                                                                           \
            if (!perf_ret) {                                                                                           \
                __sync_fetch_and_add(&stats->bytes, kernel_event_size + 4);                                            \
                __sync_fetch_and_add(&stats->count, 1);                                                                \
            } else {                                                                                                   \
                __sync_fetch_and_add(&stats->lost, 1);                                                                 \
            }                                                                                                          \
        }                                                                                                              \
    }                                                                                                                  \

#define send_event(ctx, event_type, kernel_event)                                                                      \
    u64 size = sizeof(kernel_event);                                                                                   \
    u64 use_ring_buffer;                                                                                               \
    LOAD_CONSTANT("use_ring_buffer", use_ring_buffer);                                                                 \
    if (use_ring_buffer) {                                                                                             \
        send_event_with_size_ringbuf(ctx, event_type, kernel_event, size)                                              \
    } else {                                                                                                           \
        send_event_with_size_perf(ctx, event_type, kernel_event, size)                                                 \
    }                                                                                                                  \

#define send_event_with_size(ctx, event_type, kernel_event, size)                                                      \
    u64 use_ring_buffer;                                                                                               \
    LOAD_CONSTANT("use_ring_buffer", use_ring_buffer);                                                                 \
    if (use_ring_buffer) {                                                                                             \
        send_event_with_size_ringbuf(ctx, event_type, kernel_event, size)                                              \
    } else {                                                                                                           \
        send_event_with_size_perf(ctx, event_type, kernel_event, size)                                                 \
    }                                                                                                                  \

#define send_event_ptr(ctx, event_type, kernel_event)                                                                  \
    u64 size = sizeof(*kernel_event);                                                                                  \
    u64 use_ring_buffer;                                                                                               \
    LOAD_CONSTANT("use_ring_buffer", use_ring_buffer);                                                                 \
    if (use_ring_buffer) {                                                                                             \
        send_event_with_size_ptr_ringbuf(ctx, event_type, kernel_event, size)                                          \
    } else {                                                                                                           \
        send_event_with_size_ptr_perf(ctx, event_type, kernel_event, size)                                             \
    }                                                                                                                  \

#define send_event_with_size_ptr(ctx, event_type, kernel_event, size)                                                  \
    u64 use_ring_buffer;                                                                                               \
    LOAD_CONSTANT("use_ring_buffer", use_ring_buffer);                                                                 \
    if (use_ring_buffer) {                                                                                             \
        send_event_with_size_ptr_ringbuf(ctx, event_type, kernel_event, size)                                          \
    } else {                                                                                                           \
        send_event_with_size_ptr_perf(ctx, event_type, kernel_event, size)                                             \
    }                                                                                                                  \

#endif
