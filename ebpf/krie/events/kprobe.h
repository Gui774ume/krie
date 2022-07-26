/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KPROBE_H_
#define _KPROBE_H_

#define KPROBE_TYPE 1
#define KRETPROBE_TYPE 2

#define REGISTER_KPROBE 1
#define UNREGISTER_KPROBE 2
#define REGISTER_KRETPROBE 3
#define UNREGISTER_KRETPROBE 4
#define ENABLE_KPROBE 5
#define DISABLE_KPROBE 6
#define DISARM_ALL_KPROBES 7
#define ARM_ALL_KPROBES 8

struct kprobe_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    u64 addr;
    u32 cmd;
    u32 kprobe_type;
    char symbol[SYMBOL_NAME_LENGTH];
};

memory_factory(kprobe_event)

int __attribute__((always_inline)) cache_kprobe(struct kprobe *p) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_KPROBE);
    if (syscall == NULL) {
        struct syscall_cache_t new_syscall = {
            .type = EVENT_KPROBE,
            .kprobe = {
                .kprobe_type = KPROBE_TYPE,
            },
        };
        cache_syscall(&new_syscall);
        syscall = peek_syscall(EVENT_KPROBE);
    }
    if (syscall == NULL) {
        // should neven happen, ignore
        return 0;
    }

    syscall->kprobe.p = p;
    return 0;
}

SEC("kprobe/register_kprobe")
int BPF_KPROBE(kprobe_register_kprobe, struct kprobe *p) {
    return cache_kprobe(p);
};

SEC("kretprobe/register_kprobe")
int BPF_KRETPROBE(kretprobe_register_kprobe, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->cmd = REGISTER_KPROBE;
    event->kprobe_type = syscall->kprobe.kprobe_type;

    struct kprobe *p = syscall->kprobe.p;
    BPF_CORE_READ_INTO(&event->addr, p, addr);
    char *symbol = NULL;
    BPF_CORE_READ_INTO(&symbol, p, symbol_name);
    bpf_probe_read_str(&event->symbol, sizeof(event->symbol), symbol);

    fill_process_context(&event->process);

    // filter event
    if (filter_out(EVENT_KPROBE, &event)) {
        return 0;
    }

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
};

SEC("kprobe/__unregister_kprobe_top")
int BPF_KPROBE(kprobe___unregister_kprobe_top, struct kprobe *p) {
    return cache_kprobe(p);
};

SEC("kretprobe/__unregister_kprobe_top")
int BPF_KRETPROBE(kretprobe___unregister_kprobe_top, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->cmd = UNREGISTER_KPROBE;
    event->kprobe_type = syscall->kprobe.kprobe_type;

    struct kprobe *p = syscall->kprobe.p;
    BPF_CORE_READ_INTO(&event->addr, p, addr);
    char *symbol = NULL;
    BPF_CORE_READ_INTO(&symbol, p, symbol_name);
    bpf_probe_read_str(&event->symbol, sizeof(event->symbol), symbol);

    fill_process_context(&event->process);

    // filter event
    if (filter_out(EVENT_KPROBE, &event)) {
        return 0;
    }

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
};

SEC("kprobe/enable_kprobe")
int BPF_KPROBE(kprobe_enable_kprobe, struct kprobe *p) {
    return cache_kprobe(p);
};

SEC("kretprobe/enable_kprobe")
int BPF_KRETPROBE(kretprobe_enable_kprobe, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->cmd = ENABLE_KPROBE;
    event->kprobe_type = syscall->kprobe.kprobe_type;

    struct kprobe *p = syscall->kprobe.p;
    BPF_CORE_READ_INTO(&event->addr, p, addr);
    char *symbol = NULL;
    BPF_CORE_READ_INTO(&symbol, p, symbol_name);
    bpf_probe_read_str(&event->symbol, sizeof(event->symbol), symbol);

    fill_process_context(&event->process);

    // filter event
    if (filter_out(EVENT_KPROBE, &event)) {
        return 0;
    }

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
};

SEC("kprobe/disable_kprobe")
int BPF_KPROBE(kprobe_disable_kprobe, struct kprobe *p) {
    return cache_kprobe(p);
};

SEC("kretprobe/disable_kprobe")
int BPF_KRETPROBE(kretprobe_disable_kprobe, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->cmd = DISABLE_KPROBE;
    event->kprobe_type = syscall->kprobe.kprobe_type;

    struct kprobe *p = syscall->kprobe.p;
    BPF_CORE_READ_INTO(&event->addr, p, addr);
    char *symbol = NULL;
    BPF_CORE_READ_INTO(&symbol, p, symbol_name);
    bpf_probe_read_str(&event->symbol, sizeof(event->symbol), symbol);

    fill_process_context(&event->process);

    // filter event
    if (filter_out(EVENT_KPROBE, &event)) {
        return 0;
    }

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
};

SEC("kprobe/register_kretprobe")
int BPF_KPROBE(kprobe_register_kretprobe, struct kretprobe *kretp) {
    struct syscall_cache_t syscall = {
        .type = EVENT_KPROBE,
        .kprobe = {
            .kprobe_type = KRETPROBE_TYPE,
        },
    };

    cache_syscall(&syscall);
    return 0;
};

SEC("kprobe/unregister_kretprobe")
int BPF_KPROBE(kprobe_unregister_kretprobe, struct kretprobe *rp) {
    struct syscall_cache_t syscall = {
        .type = EVENT_KPROBE,
        .kprobe = {
            .kprobe_type = KRETPROBE_TYPE,
        },
    };

    cache_syscall(&syscall);
    return 0;
}

__attribute__((always_inline)) int parse_input(char buf[4], u8 *res) {
	if (!buf)
		return -EINVAL;

	switch (buf[0]) {
	case 'y':
	case 'Y':
	case '1':
		*res = 1;
		return 0;
	case 'n':
	case 'N':
	case '0':
		*res = 0;
		return 0;
	case 'o':
	case 'O':
		switch (buf[1]) {
		case 'n':
		case 'N':
			*res = 1;
			return 0;
		case 'f':
		case 'F':
			*res = 0;
			return 0;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return -EINVAL;
}

SEC("kprobe/write_enabled_file_bool")
int BPF_KPROBE(kprobe_write_enabled_file_bool, struct file *file, char *user_buf) {
    char buf[4] = {};
    u8 enabled = 0;
    bpf_probe_read_str(&buf, sizeof(buf), user_buf);

    if (parse_input(buf, &enabled) != 0) {
        // ignore this is a bogus request
        return 0;
    }

    struct syscall_cache_t syscall = {
        .type = EVENT_KPROBE,
        .kprobe = {
            .kprobe_type = KPROBE_TYPE,
            .write_enabled_file_bool = enabled,
        },
    };

    cache_syscall(&syscall);
    return 0;
}

SEC("kretprobe/write_enabled_file_bool")
int BPF_KPROBE(kretprobe_write_enabled_file_bool, int retval) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_KPROBE);
    if (!syscall) {
        return 0;
    }

    struct kprobe_event_t *event = new_kprobe_event();
    if (event == NULL) {
        // ignore, should never happen
        return 0;
    }
    event->event.retval = retval;
    event->kprobe_type = syscall->kprobe.kprobe_type;
    if (syscall->kprobe.write_enabled_file_bool) {
        event->cmd = ARM_ALL_KPROBES;
    } else {
        event->cmd = DISARM_ALL_KPROBES;
    }

    fill_process_context(&event->process);

    // filter event
    if (filter_out(EVENT_KPROBE, &event)) {
        return 0;
    }

    int perf_ret;
    send_event_ptr(ctx, EVENT_KPROBE, event);
    return 0;
}

#endif