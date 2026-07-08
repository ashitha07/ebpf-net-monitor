
# ebpf-net-monitor

An eBPF-based TCP connection monitor that traces outbound connections 
at the Linux kernel level using kprobes on `tcp_connect()`.

## How It Works
- Attaches a kprobe to the kernel's `tcp_connect()` function
- Reads src/dst IP and port from `struct sock` using BPF CO-RE
- Passes structured events to userspace via a ring buffer map

## Architecture
Kernel: tcp_connect() → kprobe → BPF program → ring buffer
↓
Userspace: event reader → JSON output

## Tech Stack
- eBPF / libbpf / BPF CO-RE
- C (kernel BPF programs)
- Linux kprobes, ring buffer maps
- Ubuntu 24.04, Kernel 6.8, Azure

## Build
```bash
sudo apt install clang llvm libelf-dev libbpf-dev linux-tools-azure
git clone https://github.com/libbpf/libbpf-bootstrap
# copy kernel/ and userspace/ files into libbpf-bootstrap/examples/c/
make -C examples/c tcp_trace
sudo ./examples/c/tcp_trace
```

## Status
- [x] kprobe attached to `tcp_connect()`
- [x] Extracts src/dst IP and port from `struct sock` via BPF CO-RE
- [x] Ring buffer map for kernel→userspace event passing
- [ ] Userspace ring buffer reader (in progress)
- [ ] Port scan detection
- [ ] OpenSearch export
- [ ] iptables auto-blocking