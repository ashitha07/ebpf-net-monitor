#!/bin/bash
set -e

SRC=/workspaces/ebpf-net-monitor
BUILD=$SRC/libbpf-bootstrap/examples/c

echo "Copying source files..."
cp $SRC/kernel/tcp_trace.bpf.c $BUILD/
cp $SRC/kernel/tcp_trace.h $BUILD/
cp $SRC/userspace/tcp_trace.c $BUILD/
cp $SRC/userspace/detector.c $BUILD/
cp $SRC/userspace/detector.h $BUILD/

echo "Building..."
make -C $BUILD tcp_trace

echo "Done. Run with: sudo $BUILD/tcp_trace"