/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SYSCALL_CHECK_H__
#define _SYSCALL_CHECK_H__

#define MAX_SYSCALL_NR      448
#define MAX_IA32_SYSCALL_NR 450

struct syscall_table_selector_t {
    u32 syscall_nr;
    u32 syscall_table;
};

struct syscall_table_entry_t {
    u64 syscall_handler_addr;
    u64 init_event_lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct syscall_table_selector_t);
	__type(value, struct syscall_table_entry_t);
	__uint(max_entries, 3*MAX_IA32_SYSCALL_NR);
} syscall_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 3*MAX_IA32_SYSCALL_NR);
} syscall_table_lock SEC(".maps");

struct syscall_table_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    struct syscall_table_selector_t syscall;
    u64 init_addr;
    u64 new_addr;
};

memory_factory(syscall_table_event)

__attribute__((always_inline)) bool lock_syscall_table(u32 key) {
    return bpf_map_update_elem(&syscall_table_lock, &key, &key, BPF_NOEXIST);
};

__attribute__((always_inline)) int check_syscall_addr(u64 addr, u64 _stext, u64 _etext) {
    return (addr > _stext) && (addr < _etext);
};

struct check_syscall_t {
    struct syscall_table_selector_t key;
    struct syscall_table_entry_t new_entry;
    struct syscall_table_entry_t *entry;

    u64 *syscall_table_sym;
    u64 _stext;
    u64 _etext;

    struct syscall_table_event_t *event;
    u32 event_type;
};

__attribute__((always_inline)) void check_syscall(void *ctx, struct check_syscall_t *input, u8 *hooked) {
    u64 addr;

    input->entry = bpf_map_lookup_elem(&syscall_table, &input->key);
    bpf_probe_read_kernel(&addr, sizeof(addr), &input->syscall_table_sym[input->key.syscall_nr]);
    if (addr == 0) {
        // ignore this syscall
        return;
    }

    if (input->entry == NULL && lock_syscall_table(input->key.syscall_nr)) {
        input->new_entry.syscall_handler_addr = addr;
        bpf_map_update_elem(&syscall_table, &input->key, &input->new_entry, BPF_ANY);
        input->entry = bpf_map_lookup_elem(&syscall_table, &input->key);
    } else {
        input->new_entry.syscall_handler_addr = 0;
    }
    if (input->entry == NULL) {
        // someone else has the lock on that syscall, ignore
        return;
    }

    // check addr now
    if (!check_syscall_addr(addr, input->_stext, input->_etext) || input->entry->syscall_handler_addr != addr) {
        // send event
        input->event->init_addr = input->entry->syscall_handler_addr;
        input->event->new_addr = addr;
        input->event->syscall = input->key;
        int perf_ret;
        send_event_ptr(ctx, input->event_type, input->event);
        if (perf_ret == 0 && input->new_entry.syscall_handler_addr == addr) {
            input->entry->init_event_lock = 1;
        }

        // notify that the syscall was hooked
        *hooked = 1;
    }
};

__attribute__((always_inline)) u32 run_syscall_check(void *ctx, struct process_context_t *process_ctx, void *data) {
    // lookup syscall policy
    u32 event_type = EVENT_HOOKED_SYSCALL;
    fetch_policy_or_block(event_type)

    struct syscall_table_selector_t *key = (struct syscall_table_selector_t *)data;
    if (key == NULL) {
        // should never happen, ignore
        return KRIE_ACTION_NOP;
    }

    // check the requested syscall
    struct check_syscall_t input = {
        ._stext = (u64)get_kallsyms_addr(KALLSYMS_STEXT),
        ._etext = (u64)get_kallsyms_addr(KALLSYMS_ETEXT),
        .event = new_syscall_table_event(),
        .event_type = EVENT_HOOKED_SYSCALL,
    };
    if (input.event == NULL) {
        // ignore, should not happen
        return KRIE_ACTION_NOP;
    }
    copy_process_ctx(&input.event->process, process_ctx);

    // select the right syscall table
    switch (key->syscall_table) {
        case KALLSYMS_SYS_CALL_TABLE:
            input.syscall_table_sym = get_kallsyms_addr(KALLSYMS_SYS_CALL_TABLE);
            break;
        case KALLSYMS_X32_SYS_CALL_TABLE:
            input.syscall_table_sym = get_kallsyms_addr(KALLSYMS_X32_SYS_CALL_TABLE);
            break;
        case KALLSYMS_IA32_SYS_CALL_TABLE:
            input.syscall_table_sym = get_kallsyms_addr(KALLSYMS_IA32_SYS_CALL_TABLE);
            break;
    }

    u8 hooked = 0;
    check_syscall(ctx, &input, &hooked);

    // apply policy action
    if (hooked) {
        return policy->action;
    }
    return KRIE_ACTION_NOP;
};

__attribute__((always_inline)) u32 run_syscall_table_check(void *ctx) {
    // lookup syscall table policy
    u32 event_type = EVENT_HOOKED_SYSCALL_TABLE;
    fetch_policy_or_log(event_type)

    // fetch syscall tables symbol addresses
    struct check_syscall_t input = {
        ._stext = (u64)get_kallsyms_addr(KALLSYMS_STEXT),
        ._etext = (u64)get_kallsyms_addr(KALLSYMS_ETEXT),
        .event = new_syscall_table_event(),
        .event_type = EVENT_HOOKED_SYSCALL_TABLE,
    };
    if (input.event == NULL) {
        // ignore, should not happen
        return KRIE_ACTION_NOP;
    }

    // randomly select one of the three syscall tables
    u64 ts = bpf_ktime_get_ns();
    switch (ts % 3) {
        case 0:
            input.syscall_table_sym = get_kallsyms_addr(KALLSYMS_SYS_CALL_TABLE);
            input.key.syscall_table = KALLSYMS_SYS_CALL_TABLE;
            break;
        case 1:
            input.syscall_table_sym = get_kallsyms_addr(KALLSYMS_X32_SYS_CALL_TABLE);
            input.key.syscall_table = KALLSYMS_X32_SYS_CALL_TABLE;
            break;
        case 2:
            input.syscall_table_sym = get_kallsyms_addr(KALLSYMS_IA32_SYS_CALL_TABLE);
            input.key.syscall_table = KALLSYMS_IA32_SYS_CALL_TABLE;
            break;
    }

    // loop through syscall tables
    u8 hooked = 0;
    if (input.syscall_table_sym != NULL) {
        #pragma unroll
        for (int i = 1; i <= MAX_SYSCALL_NR; i++) {
            input.key.syscall_nr = i;
            check_syscall(ctx, &input, &hooked);
        }
    }

    // apply policy action
    if (hooked) {
        return policy->action;
    }
    return KRIE_ACTION_NOP;
};

#endif