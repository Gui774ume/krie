/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _RAW_SYSCALLS_H_
#define _RAW_SYSCALLS_H_

struct tracepoint_raw_syscalls_sys_enter_t
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long id;
    long args[6];
};

__attribute__((always_inline)) u32 get_active_syscall_table(struct tracepoint_raw_syscalls_sys_enter_t *args) {
    // check if the current syscall is a ia32 syscall
	u32 status;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	BPF_CORE_READ_INTO(&status, task, thread_info.status);

	if (status & 0x0002) { // TS_COMPAT
	    return KALLSYMS_IA32_SYS_CALL_TABLE;
	}
	return KALLSYMS_SYS_CALL_TABLE;
};

#define SYS_ENTER_SYSCALL_X32_PROG 0
#define SYS_ENTER_KERNEL_PARAMETER_PROG 1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 2);
} sys_enter_progs SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter_syscall")
int sys_enter_syscall(struct tracepoint_raw_syscalls_sys_enter_t *args) {
    // create process context for KRIE detection
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(process_ctx);

    // prepare krie check
    struct syscall_table_selector_t input = {
        .syscall_nr = (u32)args->id,
        .syscall_table = get_active_syscall_table(args),
    };

	u32 action = krie_run_syscall_detection(args, process_ctx, &input);
    krie_tp_enforce_policy(args, process_ctx, action);

    // jump to the next check
    bpf_tail_call(args, &sys_enter_progs, SYS_ENTER_SYSCALL_X32_PROG);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter_syscall_x32")
int sys_enter_syscall_x32(struct tracepoint_raw_syscalls_sys_enter_t *args) {
    // create process context for KRIE detection
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(process_ctx);

    // prepare krie check
    struct syscall_table_selector_t input = {
        .syscall_nr = (u32)args->id,
        .syscall_table = get_active_syscall_table(args),
    };

	if (input.syscall_table == KALLSYMS_SYS_CALL_TABLE) {
	    // check the x32 table
	    input.syscall_table = KALLSYMS_X32_SYS_CALL_TABLE;

        u32 action = krie_run_syscall_detection(args, process_ctx, &input);
        krie_tp_enforce_policy(args, process_ctx, action);
    }

    // jump to the next check
    bpf_tail_call(args, &sys_enter_progs, SYS_ENTER_KERNEL_PARAMETER_PROG);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter_kernel_parameter")
int sys_enter_kernel_parameter(struct tracepoint_raw_syscalls_sys_enter_t *args) {
    // create process context for KRIE detection
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(process_ctx);

	u32 action = krie_run_kernel_parameter_detection(args, process_ctx);
    return krie_tp_enforce_policy(args, process_ctx, action);
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 64);
} sys_exit_progs SEC(".maps");

// used as a fallback, because tracepoints are not enable when using a ia32 userspace application with a x64 kernel
// cf. https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/ftrace.h#L106
int __attribute__((always_inline)) handle_sys_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_ANY);
    if (!syscall) {
        return 0;
    }

    bpf_tail_call(args, &sys_exit_progs, syscall->type);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    if (get_raw_syscall_tracepoint_fallback()) {
        handle_sys_exit(args);
    }

    // create process context for KRIE detection
    struct process_context_t *process_ctx = new_process_context();
    if (process_ctx == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(process_ctx);

    // we're about to allow this call to go through, double check with KRIE
    u32 action = krie_run_event_check(args, process_ctx, NULL);
    return krie_tp_enforce_policy(args, process_ctx, action);
}

#endif
