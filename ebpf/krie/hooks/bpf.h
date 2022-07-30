/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _BPF_H_
#define _BPF_H_

struct bpf_map_t {
    u32 id;
    enum bpf_map_type map_type;
    char name[BPF_OBJ_NAME_LEN];
};

struct bpf_prog_t {
    u32 id;
    enum bpf_prog_type prog_type;
    enum bpf_attach_type attach_type;
    u32 padding;
    u64 helpers[3];
    char name[BPF_OBJ_NAME_LEN];
    char tag[BPF_TAG_SIZE];
};

struct bpf_tgid_fd_t {
    u32 tgid;
    u32 fd;
};

struct bpf_event_t {
    struct kernel_event_t event;
    struct process_context_t process;

    struct bpf_map_t map;
    struct bpf_prog_t prog;
    int cmd;
    u32 padding;
};

memory_factory(bpf_event)

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, struct bpf_map_t);
    __uint(max_entries, 4096);
} bpf_maps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, struct bpf_prog_t);
    __uint(max_entries, 4096);
} bpf_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct bpf_tgid_fd_t);
    __type(value, u32);
    __uint(max_entries, 4096);
} tgid_fd_map_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct bpf_tgid_fd_t);
    __type(value, u32);
    __uint(max_entries, 4096);
} tgid_fd_prog_id SEC(".maps");

SYSCALL_KPROBE3(bpf, int, cmd, union bpf_attr_def*, uattr, unsigned int, size) {
    struct syscall_cache_t syscall = {
        .type = EVENT_BPF,
        .bpf = {
            .cmd = cmd,
        }
    };
    bpf_probe_read(&syscall.bpf.attr, sizeof(syscall.bpf.attr), &uattr);

    cache_syscall(&syscall);

    // create process context for KRIE detection
    struct bpf_event_t *event = new_bpf_event();
    if (event == NULL) {
        // should never happen
        return 0;
    }
    fill_process_context(&event->process);

    // we're about to allow this call to go through, double check with KRIE
    u32 action = krie_run_detections(ctx, KRIE_EVENT_CHECK, &event->process, &syscall.type);

    // pop cache if need be
    if (action > KRIE_ACTION_LOG) {
        pop_syscall(EVENT_BPF);
    }

    return krie_syscall_kprobe_enforce_policy(ctx, &event->process, action);
}

__attribute__((always_inline)) void save_obj_fd(struct syscall_cache_t *syscall) {
    struct bpf_tgid_fd_t key = {
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .fd = syscall->bpf.retval,
    };

    u32 id = 0;

    switch (syscall->bpf.cmd) {
    case BPF_MAP_CREATE:
    case BPF_MAP_GET_FD_BY_ID:
        id = syscall->bpf.map_id;
        bpf_map_update_elem(&tgid_fd_map_id, &key, &id, BPF_ANY);
        break;
    case BPF_PROG_LOAD:
    case BPF_PROG_GET_FD_BY_ID:
        id = syscall->bpf.prog_id;
        bpf_map_update_elem(&tgid_fd_prog_id, &key, &id, BPF_ANY);
        break;
    }
}

__attribute__((always_inline)) u32 fetch_map_id(int fd) {
    struct bpf_tgid_fd_t key = {
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .fd = fd,
    };

    u32 *map_id = bpf_map_lookup_elem(&tgid_fd_map_id, &key);
    if (map_id == NULL) {
        return 0;
    }
    return *map_id;
}

__attribute__((always_inline)) u32 fetch_prog_id(int fd) {
    struct bpf_tgid_fd_t key = {
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .fd = fd,
    };

    u32 *prog_id = bpf_map_lookup_elem(&tgid_fd_prog_id, &key);
    if (prog_id == NULL) {
        return 0;
    }
    return *prog_id;
}

__attribute__((always_inline)) void populate_map_id_and_prog_id(struct syscall_cache_t *syscall) {
    int fd = 0;

    switch (syscall->bpf.cmd) {
    case BPF_MAP_LOOKUP_ELEM:
    case BPF_MAP_UPDATE_ELEM:
    case BPF_MAP_DELETE_ELEM:
    case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
    case BPF_MAP_GET_NEXT_KEY:
    case BPF_MAP_FREEZE:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->map_fd);
        syscall->bpf.map_id = fetch_map_id(fd);
        break;
    case BPF_PROG_ATTACH:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->attach_bpf_fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_PROG_DETACH:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->target_fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_PROG_QUERY:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->query.target_fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_PROG_TEST_RUN:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->test.prog_fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_PROG_GET_NEXT_ID:
        bpf_probe_read(&syscall->bpf.prog_id, sizeof(syscall->bpf.prog_id), &syscall->bpf.attr->start_id);
        break;
    case BPF_MAP_GET_NEXT_ID:
        bpf_probe_read(&syscall->bpf.map_id, sizeof(syscall->bpf.prog_id), &syscall->bpf.attr->start_id);
        break;
    case BPF_OBJ_GET_INFO_BY_FD:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->info.bpf_fd);
        syscall->bpf.map_id = fetch_map_id(fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_OBJ_PIN:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->bpf_fd);
        syscall->bpf.map_id = fetch_map_id(fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_RAW_TRACEPOINT_OPEN:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->raw_tracepoint.prog_fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_TASK_FD_QUERY:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->task_fd_query.fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_MAP_LOOKUP_BATCH:
    case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
    case BPF_MAP_UPDATE_BATCH:
    case BPF_MAP_DELETE_BATCH:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->batch.map_fd);
        syscall->bpf.map_id = fetch_map_id(fd);
        break;
    case BPF_LINK_CREATE:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->link_create.prog_fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_LINK_UPDATE:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->link_update.old_prog_fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    case BPF_PROG_BIND_MAP:
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->prog_bind_map.map_fd);
        syscall->bpf.map_id = fetch_map_id(fd);
        bpf_probe_read(&fd, sizeof(fd), &syscall->bpf.attr->prog_bind_map.prog_fd);
        syscall->bpf.prog_id = fetch_prog_id(fd);
        break;
    }
}

__attribute__((always_inline)) void fill_from_syscall_args(struct syscall_cache_t *syscall, struct bpf_event_t *event) {
    switch (event->cmd) {
    case BPF_MAP_CREATE:
        bpf_probe_read(&event->map.map_type, sizeof(event->map.map_type), &syscall->bpf.attr->map_type);
        bpf_probe_read(&event->map.name, sizeof(event->map.name), &syscall->bpf.attr->map_name);
        break;
    case BPF_PROG_LOAD:
        bpf_probe_read(&event->prog.prog_type, sizeof(event->prog.prog_type), &syscall->bpf.attr->prog_type);
        bpf_probe_read(&event->prog.name, sizeof(event->prog.name), &syscall->bpf.attr->prog_name);
        bpf_probe_read(&event->prog.attach_type, sizeof(event->prog.attach_type), &syscall->bpf.attr->expected_attach_type);
        break;
    }
}

__attribute__((always_inline)) struct process_context_t *send_bpf_event(void *ctx, struct syscall_cache_t *syscall, u32 *action) {
    struct bpf_event_t *event = new_bpf_event();
    if (event == NULL) {
        // should never happen
        return 0;
    }
    event->event.type = EVENT_BPF;
    event->event.retval = syscall->bpf.retval;
    event->cmd = syscall->bpf.cmd;

    fill_process_context(&event->process);

    u32 id = 0;

    // select map if applicable
    if (syscall->bpf.map_id != 0) {
        id = syscall->bpf.map_id;
        struct bpf_map_t *map = bpf_map_lookup_elem(&bpf_maps, &id);
        if (map != NULL) {
            event->map = *map;
        }
    }

    // select prog if applicable
    if (syscall->bpf.prog_id != 0) {
        id = syscall->bpf.prog_id;
        struct bpf_prog_t *prog = bpf_map_lookup_elem(&bpf_progs, &id);
        if (prog != NULL) {
            event->prog = *prog;
        }
    }

    if (event->cmd == BPF_PROG_LOAD || event->cmd == BPF_MAP_CREATE) {
        // fill metadata from syscall arguments
        fill_from_syscall_args(syscall, event);
    }

    // filter krie runtime
    if (filter_krie_runtime()) {
        return 0;
    }

    // run KRIE detections
    event->event.action = krie_run_detections(ctx, KRIE_EVENT_CHECK, &event->process, &event->event.type);
    *action = event->event.action;

    // send event
    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return &event->process;
}

__attribute__((always_inline)) struct process_context_t *sys_bpf_ret(void *ctx, int retval, u32 *action) {
    struct syscall_cache_t *syscall = pop_syscall(EVENT_BPF);
    if (!syscall) {
        return 0;
    }

    syscall->bpf.retval = retval;

    // save file descriptor <-> map_id mapping if applicable
    if (syscall->bpf.map_id != 0 || syscall->bpf.prog_id != 0) {
        save_obj_fd(syscall);
    }

    // populate map_id or prog_id if applicable
    populate_map_id_and_prog_id(syscall);

    // send monitoring event
    return send_bpf_event(ctx, syscall, action);
}

SYSCALL_KRETPROBE(bpf) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = sys_bpf_ret(ctx, (int)PT_REGS_RC(ctx), &action);
    if (process_ctx == NULL) {
        // ignore
        return 0;
    }

    return krie_syscall_kprobe_enforce_policy(ctx, process_ctx, action);
}

SEC("tracepoint/handle_sys_bpf_exit")
int tracepoint_handle_sys_bpf_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    u32 action = KRIE_ACTION_NOP;
    struct process_context_t *process_ctx = sys_bpf_ret(args, args->ret, &action);
    if (process_ctx == NULL) {
        // ignore
        return 0;
    }

    return krie_tp_enforce_policy(args, process_ctx, action);
}

SEC("kprobe/security_bpf_map")
int BPF_KPROBE(kprobe_security_bpf_map, struct bpf_map *map) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_BPF);
    if (!syscall) {
        return 0;
    }

    // collect relevant map metadata
    struct bpf_map_t m = {};
    BPF_CORE_READ_INTO(&m.id, map, id);
    if (bpf_core_field_exists(map->name)) {
        BPF_CORE_READ_INTO(&m.name, map, name);
    }
    if (bpf_core_field_exists(map->map_type)) {
        BPF_CORE_READ_INTO(&m.map_type, map, map_type);
    }

    // save map metadata
    bpf_map_update_elem(&bpf_maps, &m.id, &m, BPF_ANY);

    // update context
    syscall->bpf.map_id = m.id;
    return 0;
}

SEC("kprobe/security_bpf_prog")
int BPF_KPROBE(kprobe_security_bpf_prog, struct bpf_prog *prog) {
    struct syscall_cache_t *syscall = peek_syscall(EVENT_BPF);
    if (!syscall) {
        return 0;
    }

    // collect relevant prog metadata
    struct bpf_prog_t p = {};
    BPF_CORE_READ_INTO(&p.id, prog, aux, id);
    if (bpf_core_field_exists(prog->type)) {
        BPF_CORE_READ_INTO(&p.prog_type, prog, type);
    }
    if (bpf_core_field_exists(prog->expected_attach_type)) {
        BPF_CORE_READ_INTO(&p.attach_type, prog, expected_attach_type);
    }
    if (bpf_core_field_exists(prog->aux->name)) {
        BPF_CORE_READ_INTO(&p.name, prog, aux, name);
    }
    if (bpf_core_field_exists(prog->tag)) {
        BPF_CORE_READ_INTO(&p.tag, prog, tag);
    }

    // update context
    syscall->bpf.prog_id = p.id;

    // add prog helpers
    p.helpers[0] = syscall->bpf.helpers[0];
    p.helpers[1] = syscall->bpf.helpers[1];
    p.helpers[2] = syscall->bpf.helpers[2];

    // save prog metadata
    bpf_map_update_elem(&bpf_progs, &p.id, &p, BPF_ANY);
    return 0;
}

#define CHECK_HELPER_CALL_FUNC_ID 1
#define CHECK_HELPER_CALL_INSN 2

SEC("kprobe/check_helper_call")
int BPF_KPROBE(kprobe_check_helper_call) {
    int func_id = 0;
    struct syscall_cache_t *syscall = peek_syscall(EVENT_BPF);
    if (!syscall) {
        return 0;
    }

    u64 input = get_check_helper_call_input();
    if (input == CHECK_HELPER_CALL_FUNC_ID) {
        func_id = (int)PT_REGS_PARM2(ctx);
    } else if (input == CHECK_HELPER_CALL_INSN) {
        struct bpf_insn *insn = (struct bpf_insn *)PT_REGS_PARM2(ctx);
        if (bpf_core_field_exists(insn->imm)) {
            BPF_CORE_READ_INTO(&func_id, insn, imm);
        }
    }

    if (func_id >= 128) {
        syscall->bpf.helpers[2] |= (u64) 1 << (func_id - 128);
    } else if (func_id >= 64) {
        syscall->bpf.helpers[1] |= (u64) 1 << (func_id - 64);
    } else if (func_id >= 0) {
        syscall->bpf.helpers[0] |= (u64) 1 << (func_id);
    }
    return 0;
}

#endif
