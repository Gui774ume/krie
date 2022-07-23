/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PROCESS_H_
#define _PROCESS_H_

struct cgroup_context_t {
    u32 subsystem_id;
    u32 id;
    char name[CGROUP_MAX_LENGTH];
};

struct credentials_context_t {
    kuid_t          uid;		/* real UID of the task */
    kgid_t          gid;		/* real GID of the task */
    kuid_t          suid;		/* saved UID of the task */
    kgid_t          sgid;		/* saved GID of the task */
    kuid_t          euid;		/* effective UID of the task */
    kgid_t          egid;		/* effective GID of the task */
    kuid_t          fsuid;		/* UID for VFS ops */
    kgid_t          fsgid;		/* GID for VFS ops */
    unsigned        securebits;	/* SUID-less security management */
    u32             padding;
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;	/* caps we're permitted */
    kernel_cap_t    cap_effective;	/* caps we can actually use */
    kernel_cap_t    cap_bset;	/* capability bounding set */
    kernel_cap_t    cap_ambient;	/* Ambient capability set */
};

struct namespace_context_t {
    u32 cgroup_namespace;
    u32 ipc_namespace;
    u32 net_namespace;
    u32 mnt_namespace;
    u32 pid_namespace;
    u32 time_namespace;
    u32 user_namespace;
    u32 uts_namespace;
};

struct process_context_t {
    struct namespace_context_t namespaces;
    struct credentials_context_t credentials;
    char comm[TASK_COMM_LEN];
    struct cgroup_context_t cgroups[CGROUP_SUBSYS_COUNT + 1];
    u32 pid;
    u32 tid;
};

__attribute__((always_inline)) int fill_process_context(struct process_context_t *ctx) {
    // fetch current task
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    // fetch process comm and ids
    bpf_get_current_comm(ctx->comm, sizeof(ctx->comm));
    u64 id = bpf_get_current_pid_tgid();
    ctx->pid = id >> 32;
    ctx->tid = id;

    // fetch cgroup data
    char *container_id;
    #pragma unroll
    for (u32 i = 0; i <= CGROUP_SUBSYS_COUNT; i++) {
        ctx->cgroups[i].subsystem_id = i;
        BPF_CORE_READ_INTO(&ctx->cgroups[i].id, task, cgroups, subsys[i], id);
        BPF_CORE_READ_INTO(&container_id, task, cgroups, subsys[i], cgroup, kn, name);
        bpf_probe_read_str(ctx->cgroups[i].name, sizeof(ctx->cgroups[i].name), container_id);
    }

    // fetch process credentials
    BPF_CORE_READ_INTO(&ctx->credentials.uid, task, cred, uid);
    BPF_CORE_READ_INTO(&ctx->credentials.gid, task, cred, gid);
    BPF_CORE_READ_INTO(&ctx->credentials.suid, task, cred, suid);
    BPF_CORE_READ_INTO(&ctx->credentials.sgid, task, cred, sgid);
    BPF_CORE_READ_INTO(&ctx->credentials.euid, task, cred, euid);
    BPF_CORE_READ_INTO(&ctx->credentials.egid, task, cred, egid);
    BPF_CORE_READ_INTO(&ctx->credentials.fsuid, task, cred, fsuid);
    BPF_CORE_READ_INTO(&ctx->credentials.fsgid, task, cred, fsgid);
    BPF_CORE_READ_INTO(&ctx->credentials.securebits, task, cred, securebits);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_inheritable, task, cred, cap_inheritable);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_permitted, task, cred, cap_permitted);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_effective, task, cred, cap_effective);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_bset, task, cred, cap_bset);
    BPF_CORE_READ_INTO(&ctx->credentials.cap_ambient, task, cred, cap_ambient);

    // fetch process namespaces
    BPF_CORE_READ_INTO(&ctx->namespaces.cgroup_namespace, task, nsproxy, cgroup_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.ipc_namespace, task, nsproxy, ipc_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.net_namespace, task, nsproxy, net_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.mnt_namespace, task, nsproxy, mnt_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.pid_namespace, task, nsproxy, pid_ns_for_children, ns.inum);
    if (bpf_core_field_exists(task->nsproxy->time_ns->ns.inum)) {
        BPF_CORE_READ_INTO(&ctx->namespaces.time_namespace, task, nsproxy, time_ns, ns.inum);
    }
    BPF_CORE_READ_INTO(&ctx->namespaces.user_namespace, task, cred, user_ns, ns.inum);
    BPF_CORE_READ_INTO(&ctx->namespaces.uts_namespace, task, nsproxy, uts_ns, ns.inum);
    return 0;
}

#endif