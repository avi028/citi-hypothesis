#!/usr/bin/env bash
# citi-hypothesis lab setup — prepares a live tetragon environment on the
# supported base branch so any lab under citi-hypothesis/ can be run.
#
# What it does:
#   1. checks prerequisites (root, docker, go, bpf objects)
#   2. warns if the repo is not on the supported base branch
#   3. builds ./tetragon and ./tetra (BUILD=0 to skip)
#   4. starts tetragon with the local BPF objects (unless one is already up)
#   5. starts a `tetra getevents` capture into $RUN_DIR/events.jsonl
#
# Usage:
#   sudo citi-hypothesis/setup.sh
#
# Environment overrides: BASE_BRANCH, RUN_DIR, BUILD, TETRAGON, TETRA,
# BPF_LIB, TETRAGON_ARGS (extra agent flags, e.g. --enable-ancestors).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

BASE_BRANCH=${BASE_BRANCH:-release/v1.6-1-q5}
RUN_DIR=${RUN_DIR:-/tmp/citi-labs}
BUILD=${BUILD:-1}
TETRAGON=${TETRAGON:-$ROOT/tetragon}
TETRA=${TETRA:-$ROOT/tetra}
BPF_LIB=${BPF_LIB:-$ROOT/bpf/objs}
TETRAGON_ARGS=${TETRAGON_ARGS:-}

say() { echo "[setup] $*"; }
die() { echo "[setup] FAIL: $*" >&2; exit 1; }

# ── 1. prerequisites ─────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "run as root (sudo citi-hypothesis/setup.sh)"
command -v docker >/dev/null || die "docker is required"
docker ps >/dev/null 2>&1   || die "docker daemon not accessible"
command -v go >/dev/null    || die "go toolchain is required"
command -v python3 >/dev/null || die "python3 is required"

# ── 2. base branch ───────────────────────────────────────────────────────────
branch=$(git -C "$ROOT" branch --show-current 2>/dev/null || true)
if [[ "$branch" != "$BASE_BRANCH" ]]; then
    say "WARNING: repo is on '$branch', labs are verified on '$BASE_BRANCH'."
    say "         Results may differ — 'git checkout $BASE_BRANCH' recommended."
fi

# ── 3. build ─────────────────────────────────────────────────────────────────
if [[ "$BUILD" == 1 ]]; then
    say "building tetragon + tetra (this can take a minute)"
    (cd "$ROOT" && go build -mod=mod -o tetragon ./cmd/tetragon/)
    (cd "$ROOT" && go build -mod=mod -o tetra   ./cmd/tetra/)
fi
[[ -x "$TETRAGON" ]] || die "missing tetragon binary: $TETRAGON"
[[ -x "$TETRA" ]]    || die "missing tetra binary: $TETRA"
[[ -d "$BPF_LIB" ]]  || die "missing BPF objects: $BPF_LIB (run: make tetragon-bpf-local LOCAL_CLANG=1)"

mkdir -p "$RUN_DIR"

# ── 4. tetragon agent ────────────────────────────────────────────────────────
if (: >/dev/tcp/127.0.0.1/54321) 2>/dev/null; then
    say "tetragon gRPC already listening on 127.0.0.1:54321 — reusing it"
else
    say "starting tetragon (log: $RUN_DIR/tetragon.log)"
    # shellcheck disable=SC2086
    "$TETRAGON" --bpf-lib "$BPF_LIB" $TETRAGON_ARGS >"$RUN_DIR/tetragon.log" 2>&1 &
    echo $! >"$RUN_DIR/tetragon.pid"
    for _ in $(seq 1 60); do
        (: >/dev/tcp/127.0.0.1/54321) 2>/dev/null && break
        sleep 1
    done
    (: >/dev/tcp/127.0.0.1/54321) 2>/dev/null || { cat "$RUN_DIR/tetragon.log" >&2; die "tetragon did not start"; }
fi

# ── 5. event capture ─────────────────────────────────────────────────────────
if [[ -f "$RUN_DIR/tetra.pid" ]] && kill -0 "$(cat "$RUN_DIR/tetra.pid")" 2>/dev/null; then
    say "event capture already running -> $RUN_DIR/events.jsonl"
else
    : >"$RUN_DIR/events.jsonl"
    "$TETRA" getevents -o json >>"$RUN_DIR/events.jsonl" 2>"$RUN_DIR/tetra.log" &
    echo $! >"$RUN_DIR/tetra.pid"
    sleep 2
    kill -0 "$(cat "$RUN_DIR/tetra.pid")" 2>/dev/null || { cat "$RUN_DIR/tetra.log" >&2; die "tetra getevents failed"; }
fi

cat <<EOF

[setup] READY. Run a lab:

  # apply its policy (RuntimePolicy v2 is translated automatically)
  ./tetra tracingpolicy add citi-hypothesis/<LAB>/policy.yaml
  ./tetra tracingpolicy list

  # generate the activity (see the lab's RESULT.md for the docker command)
  docker run --rm debian:stable-slim sh -c '...'

  # watch the events
  tail -f $RUN_DIR/events.jsonl | python3 -m json.tool

  # when done
  ./tetra tracingpolicy delete <policy-name> --all-rules
  sudo citi-hypothesis/teardown.sh     # stops capture + tetragon

Events file : $RUN_DIR/events.jsonl
Agent log   : $RUN_DIR/tetragon.log
EOF
