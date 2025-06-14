#!/bin/bash

echo "=== Container Escape Testing Environment ==="
echo "Current user: $(whoami)"
echo "Current directory: $(pwd)"
echo "Hostname: $(hostname)"
echo "=== System Information ==="
echo "Kernel version: $(uname -a)"
echo "=== Process Information ==="
echo "Process tree:"
ps auxf
echo "=== Network Information ==="
echo "Network interfaces:"
ip a
echo "=== Mount Information ==="
echo "Mounted filesystems:"
mount
echo "=== Capabilities ==="
echo "Current capabilities:"
capsh --print
echo "=== Environment Variables ==="
env
echo "=== Container Runtime ==="
echo "Checking for container runtime:"
if [ -f /.dockerenv ]; then
    echo "Running in Docker container"
fi
if [ -f /run/.containerenv ]; then
    echo "Running in Podman container"
fi
echo "=== End of Test Information ==="