# ebpf-net-monitor

An eBPF-based TCP connection monitor that traces outbound connections 
at the Linux kernel level using kprobes on `tcp_connect()`.
