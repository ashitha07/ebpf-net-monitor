/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __TCP_TRACE_H
#define __TCP_TRACE_H

#define TASK_COMM_LEN     16

struct event {
    int pid;
    __u16 dport;    // destination port
    __u32 daddr;    // destination IP
    __u32 saddr;    // source IP
    __u16 sport;    // source port
    __u64 timestamp_ns; // timestamp in nanoseconds
    char comm[TASK_COMM_LEN]; // process name
    bool connection_event; // true if connection event, false if close event
};

#endif /* __TCP_TRACE_H */