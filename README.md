
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
- [x] Userspace ring buffer reader with structured JSON output
- [x] Port scan detection with cooldown mechanism
- [x] OpenSearch export with daily index rotation
- [x] Memory management: stale entry TTL cleanup
- [x] iptables auto-blocking on detection (--block flag)

## Future Enhancements
- XDP-based pre-kernel blocking for known malicious IPs
- Config-based IP whitelisting
- Time compression detection (fast vs slow scans)
- Connection burst detection

## How to Run

# Basic monitoring (JSON output only)
sudo ./tcp_trace | python3 -u exporter.py --no-opensearch

# With OpenSearch indexing
sudo bash -c './tcp_trace | python3 -u exporter.py'

# With auto-blocking enabled
sudo bash -c './tcp_trace | python3 -u exporter.py --block'