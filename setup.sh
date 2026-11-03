#!/usr/bin/env bash
# citi-hypothesis lab setup — prepares a live ebpf-agent environment on the
# supported base branch so any lab under citi-hypothesis/ can be run.
#
# What it does:
#   1. checks prerequisites (root, docker, go, bpf objects)
#   2. installs the citi-hypothesis-labs skill (from SKILL-INSTALL.md)
#   3. warns if the repo is not on the supported base branch
#   4. builds ./ebpf-agent and ./ebpf-operator (BUILD=0 to skip)
#   5. starts ebpf-agent with the local BPF objects (unless one is already up)
#   6. starts a `ebpf-operator getevents` capture into $RUN_DIR/events.jsonl
#
# Usage:
#   sudo citi-hypothesis/setup.sh
#
# Environment overrides: BASE_BRANCH, RUN_DIR, BUILD, EBPF_AGENT, EBPF_OPERATOR,
# BPF_LIB, EBPF_AGENT_ARGS (extra agent flags, e.g. --enable-ancestors).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

BASE_BRANCH=${BASE_BRANCH:-release/v1.6-1-q5}
RUN_DIR=${RUN_DIR:-/tmp/citi-labs}
BUILD=${BUILD:-1}
EBPF_AGENT=${EBPF_AGENT:-$ROOT/ebpf-agent}
EBPF_OPERATOR=${EBPF_OPERATOR:-$ROOT/ebpf-operator}
BPF_LIB=${BPF_LIB:-$ROOT/bpf/objs}
EBPF_AGENT_ARGS=${EBPF_AGENT_ARGS:-}

say() { echo "[setup] $*"; }
die() { echo "[setup] FAIL: $*" >&2; exit 1; }

# ── 1. prerequisites ─────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "run as root (sudo citi-hypothesis/setup.sh)"
command -v docker >/dev/null || die "docker is required"
docker ps >/dev/null 2>&1   || die "docker daemon not accessible"
command -v go >/dev/null    || die "go toolchain is required"
command -v python3 >/dev/null || die "python3 is required"

# ── 2. install the citi-hypothesis-labs skill ─────────────────────────────────
# The skill lives self-contained inside SKILL-INSTALL.md (between the
# "## Full SKILL.md content" marker and the closing fence). Extract it to
# the project skills dir so any agent session can use it — idempotent.
SKILL_INSTALL="$HERE/SKILL-INSTALL.md"
SKILL_DEST="$ROOT/.devin/skills/citi-hypothesis-labs/SKILL.md"
if [[ -f "$SKILL_INSTALL" ]]; then
    mkdir -p "$(dirname "$SKILL_DEST")"
    python3 -c 'import re,sys;t=open(sys.argv[1]).read();m=re.search(r"## Full SKILL.md content\n\n```markdown\n(.*?)\n```",t,re.S);open(sys.argv[2],"w").write(m.group(1)+"\n")' \
        "$SKILL_INSTALL" "$SKILL_DEST" \
        && say "skill installed -> $SKILL_DEST"
else
    say "SKILL-INSTALL.md not found — skipping skill install"
fi

# ── 3. base branch ───────────────────────────────────────────────────────────
branch=$(git -C "$ROOT" branch --show-current 2>/dev/null || true)
if [[ "$branch" != "$BASE_BRANCH" ]]; then
    say "WARNING: repo is on '$branch', labs are verified on '$BASE_BRANCH'."
    say "         Results may differ — 'git checkout $BASE_BRANCH' recommended."
fi

# ── 4. build ─────────────────────────────────────────────────────────────────
if [[ "$BUILD" == 1 ]]; then
    say "building ebpf-agent + ebpf-operator (this can take a minute)"
    (cd "$ROOT" && go build -mod=mod -o ebpf-agent ./cmd/ebpf-agent/)
    (cd "$ROOT" && go build -mod=mod -o ebpf-operator   ./cmd/ebpf-operator/)
fi
[[ -x "$EBPF_AGENT" ]] || die "missing ebpf-agent binary: $EBPF_AGENT"
[[ -x "$EBPF_OPERATOR" ]]    || die "missing ebpf-operator binary: $EBPF_OPERATOR"
[[ -d "$BPF_LIB" ]]  || die "missing BPF objects: $BPF_LIB (run: make ebpf-agent-bpf-local LOCAL_CLANG=1)"

mkdir -p "$RUN_DIR"

# ── 5. ebpf-agent agent ────────────────────────────────────────────────────────
if (: >/dev/tcp/127.0.0.1/54321) 2>/dev/null; then
    say "ebpf-agent gRPC already listening on 127.0.0.1:54321 — reusing it"
else
    say "starting ebpf-agent (log: $RUN_DIR/ebpf-agent.log)"
    # shellcheck disable=SC2086
    "$EBPF_AGENT" --bpf-lib "$BPF_LIB" $EBPF_AGENT_ARGS >"$RUN_DIR/ebpf-agent.log" 2>&1 &
    echo $! >"$RUN_DIR/ebpf-agent.pid"
    for _ in $(seq 1 60); do
        (: >/dev/tcp/127.0.0.1/54321) 2>/dev/null && break
        sleep 1
    done
    (: >/dev/tcp/127.0.0.1/54321) 2>/dev/null || { cat "$RUN_DIR/ebpf-agent.log" >&2; die "ebpf-agent did not start"; }
fi

# ── 6. event capture ─────────────────────────────────────────────────────────
if [[ -f "$RUN_DIR/ebpf-operator.pid" ]] && kill -0 "$(cat "$RUN_DIR/ebpf-operator.pid")" 2>/dev/null; then
    say "event capture already running -> $RUN_DIR/events.jsonl"
else
    : >"$RUN_DIR/events.jsonl"
    "$EBPF_OPERATOR" getevents -o json >>"$RUN_DIR/events.jsonl" 2>"$RUN_DIR/ebpf-operator.log" &
    echo $! >"$RUN_DIR/ebpf-operator.pid"
    sleep 2
    kill -0 "$(cat "$RUN_DIR/ebpf-operator.pid")" 2>/dev/null || { cat "$RUN_DIR/ebpf-operator.log" >&2; die "ebpf-operator getevents failed"; }
fi

cat <<EOF

[setup] READY. Run a lab:

  # apply its policy (RuntimePolicy v2 is translated automatically)
  ./ebpf-operator tracingpolicy add citi-hypothesis/<LAB>/policy.yaml
  ./ebpf-operator tracingpolicy list

  # generate the activity (see the lab's RESULT.md for the docker command)
  docker run --rm debian:stable-slim sh -c '...'

  # watch the events
  tail -f $RUN_DIR/events.jsonl | python3 -m json.tool

  # when done
  ./ebpf-operator tracingpolicy delete <policy-name> --all-rules
  sudo citi-hypothesis/teardown.sh     # stops capture + ebpf-agent

Events file : $RUN_DIR/events.jsonl
Agent log   : $RUN_DIR/ebpf-agent.log
EOF
