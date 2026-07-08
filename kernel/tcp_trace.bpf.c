#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcp_trace.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
    __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    __u32 dst_ip_addr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
    __u16 src_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    __u32 src_ip_addr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    __u64 ts = bpf_ktime_get_ns();
    struct event* e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->dport = dst_port;
    e->daddr = dst_ip_addr;
    e->sport = src_port;
    e->saddr = src_ip_addr;
    e->timestamp_ns = ts;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->connection_event = true; 

    bpf_ringbuf_submit(e, 0);
    /*
    bpf_printk("TCP connect to port %u, IP address %d.%d.%d.%d\n", dst_port, 
        (dst_ip_addr >> 24) & 0xFF, 
        (dst_ip_addr >> 16) & 0xFF, 
        (dst_ip_addr >> 8) & 0xFF, 
        dst_ip_addr & 0xFF); */
    return 0;
}