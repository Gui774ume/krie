/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SYSCTL_H_
#define _SYSCTL_H_

#define SYSCTL_SHOT     0
#define SYSCTL_OK       1
#define SYSCTL_OVERRIDE 2
#define SYSCTL_EINVAL   3
#define SYSCTL_ERANGE   4

#define MAX_SYSCTL_OBJ_LEN 256
#define MAX_SYSCTL_BUF_LEN 1024

struct sysctl_parameter_key_t {
    char name[MAX_SYSCTL_OBJ_LEN];
};

struct sysctl_parameter_value_t {
    u32 override_value_length;
    u16 block_write_access;
    u16 block_read_access;
    char value[MAX_SYSCTL_OBJ_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sysctl_parameter_key_t);
	__type(value, struct sysctl_parameter_value_t);
	__uint(max_entries, 1024);
} sysctl_parameters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct sysctl_parameter_value_t);
	__uint(max_entries, 1);
} sysctl_default SEC(".maps");

struct sysctl_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u32 write_access;
    u32 file_position;
    u64 action;
    char name_value[MAX_SYSCTL_BUF_LEN];
};

memory_factory(sysctl_event)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct process_context_t);
	__uint(max_entries, 1);
} sysctl_process_cache SEC(".maps");

SEC("kprobe/proc_sys_call_handler")
int BPF_KPROBE(kprobe_proc_sys_call_handler) {
    u32 key = 0;
    struct process_context_t *process = bpf_map_lookup_elem(&sysctl_process_cache, &key);
    if (process == NULL) {
        // should never happen
        return 0;
    }

    fill_process_context(process);
    return 0;
};

SEC("cgroup/sysctl")
int cgroup_sysctl(struct bpf_sysctl *ctx) {
    struct sysctl_event_t *event = new_sysctl_event();
    if (event == NULL) {
        // ignore, should never happen
        return SYSCTL_OK;
    }
    event->event.type = EVENT_SYSCTL;
    event->write_access = ctx->write;
    event->file_position = ctx->file_pos;

    // retrieve process context from cache
    u32 process_key = 0;
    struct process_context_t *process = bpf_map_lookup_elem(&sysctl_process_cache, &process_key);
    if (process != NULL) {
        copy_process_ctx(&event->process, process);
        bpf_map_delete_elem(&sysctl_process_cache, &process_key);
    }

    // copy the name of the control parameter
	u32 value_index = bpf_sysctl_get_name(ctx, event->name_value, MAX_SYSCTL_OBJ_LEN, 0);
	if ((int)value_index == -E2BIG) {
	    // MAX_SYSCTL_OBJ_LEN isn't big enough for the name of the control parameter, allow read access, drop write access
	    if (event->write_access) {
	        return SYSCTL_SHOT;
	    }
	    return SYSCTL_OK;
	}
    // increment the value_index to account for the trailing NULL
    value_index++;

    // lookup decision map now
    struct sysctl_parameter_value_t *decision = bpf_map_lookup_elem(&sysctl_parameters, &event->name_value[0]);
    if (decision == NULL) {
        // lookup default decision
        u32 key = 0;
        decision = bpf_map_lookup_elem(&sysctl_default, &key);
        if (decision == NULL) {
            // should never happen, ignore
            return SYSCTL_SHOT;
        }
    }

    // copy the value of the control parameter
    int new_value_index = bpf_sysctl_get_current_value(ctx, &event->name_value[value_index & (MAX_SYSCTL_BUF_LEN - 1 - 3*MAX_SYSCTL_OBJ_LEN)], MAX_SYSCTL_OBJ_LEN);
    if ((int)new_value_index == -E2BIG) {
	    // MAX_SYSCTL_OBJ_LEN isn't big enough for the value of the control parameter, allow read access, drop write access
	    if (event->write_access) {
	        return SYSCTL_SHOT;
	    }
	    return SYSCTL_OK;
	}
	// increment the new_value_index to account for the trailing NULL
	new_value_index += value_index + 1;

	// if this is a write event, copy the new value too
	int buffer_end = new_value_index;
	if (event->write_access) {
	    buffer_end = bpf_sysctl_get_new_value(ctx, &event->name_value[new_value_index & (MAX_SYSCTL_BUF_LEN - 1 - 2*MAX_SYSCTL_OBJ_LEN)], MAX_SYSCTL_OBJ_LEN);
        if ((int)buffer_end == -E2BIG) {
            // MAX_SYSCTL_OBJ_LEN isn't big enough for the new value of the control parameter, drop access
            return SYSCTL_SHOT;
	    }
	    // increment the buffer_end to account for the trailing NULL
	    buffer_end += new_value_index + 1;
	}

    // check access type
    event->action = SYSCTL_OK;
    if (event->write_access && decision->block_write_access) {
        event->action = SYSCTL_SHOT;
    }
    if (!event->write_access && decision->block_read_access) {
        event->action = SYSCTL_SHOT;
    }
    if (event->write_access && decision->override_value_length >= 1) {
        // filter out KRIE runtime
        if (!filter_krie_runtime_with_pid(event->process.pid)) {
            // override the value with the user defined one
            ctx->file_pos = 0; // make sure we're writing at the beginning of the value
            int ret = bpf_sysctl_set_new_value(ctx, &decision->value[0], MAX_SYSCTL_OBJ_LEN);
            if (ret == -EINVAL) {
                event->action = SYSCTL_EINVAL;
            }
            if (ret == -ERANGE) {
                event->action = SYSCTL_ERANGE;
            }
            event->action = SYSCTL_OVERRIDE;
        }
    }

    // run KRIE detections now
    event->event.action = krie_run_event_check(ctx, &event->process, &event->event.type);

    // send event
    int perf_ret;
    send_event_with_size_ptr(ctx, event->event.type, event, (offsetof(struct sysctl_event_t, name_value) + (buffer_end & (MAX_SYSCTL_BUF_LEN - 1))));

    if (event->action == SYSCTL_OK || event->action == SYSCTL_OVERRIDE) {
        // we're about to allow this call to go through, double check with KRIE
        return krie_cgroup_sysctl_enforce_policy(ctx, &event->process, event->event.action);
    }
    return SYSCTL_SHOT;
};

#endif