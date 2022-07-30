/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _EVENT_CHECK_H_
#define _EVENT_CHECK_H_

struct event_check_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u32 checked_event_type;
};

memory_factory(event_check_event)

__attribute__((always_inline)) u32 run_event_check(void *ctx, struct process_context_t *process_ctx, void *data) {
    if (data == NULL) {
        // should never happen, ignore
        return KRIE_ACTION_NOP;
    }
    struct event_check_event_t *event = new_event_check_event();
    if (event == NULL) {
        // should never happen, ignore
        return KRIE_ACTION_NOP;
    }
    event->event.type = EVENT_CHECK_EVENT;
    copy_process_ctx(&event->process, process_ctx);

    // lookup event policy
    event->checked_event_type = *(u32*)data;
    fetch_policy_or_block(event->checked_event_type)

    if (policy->action >= KRIE_ACTION_BLOCK) {
        event->event.action = policy->action;

        int perf_ret;
        send_event_ptr(ctx, event->event.type, event);
    }

    return policy->action;
};

#endif