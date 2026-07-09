// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <stdbool.h>
#include "tcp_trace.h"
#include "tcp_trace.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	char dst_ip[16], src_ip[16];

	snprintf(dst_ip, sizeof(dst_ip), "%d.%d.%d.%d",
    (e->daddr >> 24) & 0xFF,
    (e->daddr >> 16) & 0xFF,
    (e->daddr >> 8)  & 0xFF,
    e->daddr & 0xFF);

	snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d",
    (e->saddr >> 24) & 0xFF,
    (e->saddr >> 16) & 0xFF,
    (e->saddr >> 8)  & 0xFF,
    	e->saddr & 0xFF);
    if (e->connection_event) {
        printf("%-8s %-5s %-16s %-7d %-7d %-8s %-7d %-8s", 
                ts, "TCP CONNECT", e->comm, 
               e->pid,e->dport,
               dst_ip,
               e->sport,
               src_ip);
        printf("\n");
    } else {
        printf("%-8s %-5s %-16s %-7d %-7d %-8s %-7d %-8s", 
               ts, "TCP CLOSE", e->comm, 
               e->pid,e->dport,
               dst_ip,
               e->sport,
               src_ip);
        printf("\n");
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct tcp_trace_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    /* Open load and verify BPF application */
    skel = tcp_trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Attach tracepoint handler */
    err = tcp_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    /* Process events */
    printf("%-8s %-5s %-16s %-7s %-7s %-8s %-7s %-8s\n", "TIME", "EVENT", "COMM", "PID",
           "DESTINATION PORT","DESTINATION ADDRESS","SOURCE PORT","SOURCE ADDRESS");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    tcp_trace_bpf__destroy(skel);
    return -err;
}