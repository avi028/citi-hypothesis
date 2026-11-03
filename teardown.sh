#!/usr/bin/env bash
# Tears down a citi-hypothesis lab run started by setup.sh:
# stops the event capture, removes all loaded tracing policies, and stops
# the ebpf-agent agent it launched.
#
# Usage: sudo citi-hypothesis/teardown.sh
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
RUN_DIR=${RUN_DIR:-/tmp/citi-labs}
TETRA=${TETRA:-$ROOT/tetra}

say() { echo "[teardown] $*"; }

# stop capture
if [[ -f "$RUN_DIR/tetra.pid" ]]; then
    kill "$(cat "$RUN_DIR/tetra.pid")" 2>/dev/null || true
    rm -f "$RUN_DIR/tetra.pid"
    say "stopped event capture"
fi

# remove loaded policies (only if an agent is still reachable)
if (: >/dev/tcp/127.0.0.1/54321) 2>/dev/null; then
    "$TETRA" tracingpolicy list 2>/dev/null | awk 'NR>1 && $2 {print $2}' | while read -r name; do
        "$TETRA" tracingpolicy delete "$name" >/dev/null 2>&1 \
            && say "deleted policy $name" || true
    done
fi

# stop the agent we started
if [[ -f "$RUN_DIR/ebpf-agent.pid" ]]; then
    kill "$(cat "$RUN_DIR/ebpf-agent.pid")" 2>/dev/null || true
    rm -f "$RUN_DIR/ebpf-agent.pid"
    say "stopped ebpf-agent"
fi

say "done — artifacts kept in $RUN_DIR"
