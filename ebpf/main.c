/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

// Custom eBPF helpers
#include "include/all.h"

// krie probes
#include "krie/syscall_probe_macro.h"
#include "krie/memory_factory.h"
#include "krie/constants.h"
#include "krie/events.h"
#include "krie/process.h"
#include "krie/syscall_cache.h"
#include "krie/raw_syscalls.h"
#include "krie/krie.h"
#include "krie/filter.h"

// events
#include "krie/events/all_events.h"

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
