#!/bin/bash
# Lifecycle benchmarks for AIVisor
# Measures create→Ready, exec→first-instruction, destroy→reclaimed
#
# Usage: sudo ./bench/lifecycle/bench.sh [--json]
#
# Produces: timing report with kernel version and CPU model recorded.

set -euo pipefail

JSON="${1:-}"

KERNEL=$(uname -r)
CPU=$(grep 'model name' /proc/cpuinfo | head -1 | sed 's/.*: //')

echo "Kernel: $KERNEL"
echo "CPU: $CPU"
echo ""

if [ -n "$JSON" ]; then
    echo "JSON mode enabled"
fi

echo "=== Create → Ready ==="
for i in 1 10 100; do
    echo "Concurrency: $i"
    # TODO(phase4): use hyperfine or custom harness with --json output
    echo "  (benchmark stubbed — implement with aivisor run --json)"
done

echo ""
echo "=== Destroy → Reclaimed ==="
echo "  (benchmark stubbed — implement with aivisor destroy timing)"

echo ""
echo "=== Per-sandbox RSS ==="
echo "  (benchmark stubbed — measure via cgroup memory.current)"
