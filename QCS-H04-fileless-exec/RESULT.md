# QCS-H04 — Fileless or Inline Script Execution

## What we wanted to prove

If someone runs a script without ever saving it as a file — typing it into
the shell directly, or piping it in — does Qualys still see what it did?

## Verdict

**Partially — and the partial part matters.** You can't see the fileless
script *itself*, but you see **everything it does**: every command it
launches, every file it opens, every connection it makes, all attributed
back to the shell that ran it.

## What we did

- Wrote a policy (`policy.yaml`) watching for a canary file being opened
  and for outbound connections on web ports
- Ran two kinds of fileless execution in a container:
  - **Case 1:** `sh -c '...script...'` — script embedded in the command
  - **Case 2:** `sh` with the script fed in over standard input — nothing
    stored anywhere

## What we observed

| | Case 1: `sh -c` | Case 2: stdin |
|---|---|---|
| Interpreter seen | Yes — `/bin/sh` | Yes — `/bin/sh` |
| Script content visible | **Yes** — the whole script is in the command line | **No** — launch record shows the shell with *no arguments* |
| Child processes seen | Yes (`cat`, `wget` — with parent = the shell) | Yes (same) |
| File it touched | Canary-open event recorded | Canary-open event recorded |
| Connection it made | Egress event with full address/port/peer | Egress event, same detail |

## Compared with the file-based scenario (QCS-H03)

- A script **stored as a file** shows up by name — the launch record's
  binary is literally `/tmp/.../script.sh`.
- A script **fed over stdin** is a ghost — same behavior, same child
  activity, but the only evidence is the interpreter (`sh`) plus the trail
  of what it did. The script's text itself is never in any record.

## The "partial" explained

Detection works through **associated activity**, not the script body:

- A fileless script that touches files, spawns processes, or talks on the
  network is fully visible in *what it does*.
- A fileless script that only computes quietly in-memory would leave
  almost no trace beyond the bare interpreter launch — that is the real
  blind spot.
- Practical takeaway: detection rules for fileless attacks should target
  the *effects* (file opens, execs, egress) rather than expecting to match
  the script itself.

## memfd fileless execution — a stronger case, tested

A harder form of fileless attack stores the *binary itself* only in memory
(Linux `memfd_create`) and execs it through `/proc/self/fd/N`. We tested
it with `tools/memfd-exec.go`, which copies a real binary into RAM and runs
it — nothing ever written to disk.

**Detection: works, two independent ways.**

| Layer | What it catches | How |
|---|---|---|
| `sys_memfd_create` kprobe (`tracingpolicy.yaml`) | The moment the anonymous memory file is created — name + flags + fd, attributed to the creating process | raw Cilium policy (v2 can't express this hook yet) |
| `process_exec` event | The memory-resident exec — `binary=/proc/self/fd/4`, and `binary_properties.file.inode.links=0` meaning *"this binary exists only in memory"* | **built into the base sensor** — needs `--enable-process-cred` |

**Enforcement: works, but only at the primitive.**

- Blocking via `matchBinaries` on the exec'd path does **not** work — a
  memfd-backed exec doesn't resolve to a matchable path (`/memfd:`,
  `/proc/self/fd/`, `(deleted)` all failed; payload ran).
- Sigkill on `sys_memfd_create` (`tracingpolicy-block.yaml`) **kills the
  process at the moment it creates the memory file** — rc=137, payload
  never ran.

## Future implementation

The interpreter launch record carries no payload for stdin-fed scripts.
Capturing it would require hooking the interpreter's input read (e.g. a
read of fd 0 at exec time) — no RuntimePolicy v2 field expresses that
today; a raw Cilium TracingPolicy on the interpreter's read path could
approximate it but is out of scope for this lab.

For memfd: a future v2 `fileless`/`memfd` rule type could wrap the
`sys_memfd_create` hook (both audit and block) so no raw TracingPolicy is
needed. A `matchBinaries` extension that recognizes memory-backed bprm
files would fix the block-by-path gap.

## Point-by-point check (original hypothesis)

| # | Execution point | Status | Evidence |
|---|---|---|---|
| E1 | Inline shell via `bash -c` | **YES** (live) | `process_exec /usr/bin/bash` — argv carries the **full inline script** |
| E2 | Script via standard input | **YES** (live) | `process_exec /usr/bin/bash` argv=`-` — script body **not** visible |
| E3 | Process, file-read, and network events from the inline script | **YES** (live) | child `cat` → `security_file_open` on the canary; `tcp_connect` egress → :8080, same container |
| E4 | Interpreter, full command line, children, associated activity | **YES PARTIAL (file open)** | interpreter ✓; cmdline ✓ for `-c`, ✗ for stdin; children + file-open + network activity ✓ — matches the annotation |
| E5 | Compare with file-based script scenario | **YES** (live) | file-based exec shows binary = `/tmp/citi-h04-file.sh` (script name visible); inline/stdin show only the interpreter |

**Not covered live:** none — all points verified (stdin script body is
invisible by design, recorded in E2/E4).

## eBPF-Agent events observed (2026-11-03 quick run)

```json
// case 1 — inline `bash -c` (marker CITI-H04-inline)
{"process_exec":   {"process": {"binary": "/usr/bin/bash", "arguments": "-c \"echo CITI-H04-inline; cat /etc/citi-h04-canary.txt; exec 3<>/dev/tcp/172.17.0.1/8080\""}}}
{"process_kprobe": {"policy_name": "citi-h04-fileless-exec-v2-canary-open", "function_name": "security_file_open", "process": {"binary": "/usr/bin/cat"}}}
{"process_kprobe": {"policy_name": "citi-h04-fileless-exec-v2-egress-audit", "function_name": "tcp_connect", "process": {"binary": "/usr/bin/bash"}}}

// case 2 — stdin-fed script (marker CITI-H04-stdin): NO arguments
{"process_exec":   {"process": {"binary": "/usr/bin/bash", "arguments": "-"}}}
{"process_kprobe": {"policy_name": "citi-h04-fileless-exec-v2-canary-open", "function_name": "security_file_open", "process": {"binary": "/usr/bin/cat"}}}
{"process_kprobe": {"policy_name": "citi-h04-fileless-exec-v2-egress-audit", "function_name": "tcp_connect", "process": {"binary": "/usr/bin/bash"}}}

// case 3 — file-based script: binary IS the script path
{"process_exec":   {"process": {"binary": "/tmp/citi-h04-file.sh", "arguments": "/tmp/citi-h04-file.sh"}}}
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | canary-open + egress-audit rules |
| `tracingpolicy.yaml` | raw Cilium policy auditing `sys_memfd_create` |
| `tracingpolicy-block.yaml` | raw Cilium policy SIGKILLing `sys_memfd_create` |
| `policy-memfd-block.yaml` | v2 attempt to block memfd exec by path (did not match — documented above) |
| `tools/memfd-exec.go` | static memfd-exec demo binary (build: `CGO_ENABLED=0 go build -mod=mod`) |
| `pod.yaml` | pod running both fileless cases |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
docker network create citi-h04-net
docker run -d --name citi-h04-srv --network citi-h04-net alpine:3 \
  sh -c 'while true; do printf "HTTP/1.1 200 OK\r\n\r\nok" | nc -l -p 8080; done'
docker run -d --name citi-h04 --network citi-h04-net alpine:3 sleep 600
docker exec citi-h04 sh -c 'echo canary > /etc/citi-h04-canary.txt'

# case 1 — inline -c
docker exec citi-h04 sh -c 'echo CITI-H04-inline; cat /etc/citi-h04-canary.txt;
  wget -q -O /dev/null http://citi-h04-srv:8080'

# case 2 — stdin script
docker exec -i citi-h04 sh <<'EOF'
echo CITI-H04-stdin
cat /etc/citi-h04-canary.txt
wget -q -O /dev/null http://citi-h04-srv:8080
EOF
```

Result: both cases produced canary-open events and a tcp_connect egress
event (dest `citi-h04-srv:8080`) attributed to the `wget` child of the
shell — while only the `sh -c` case exposed the script text in its
command line.

# memfd case (agent started with --enable-process-cred)
CGO_ENABLED=0 go build -mod=mod -o /tmp/memfd-exec \
  citi-hypothesis/QCS-H04-fileless-exec/tools/memfd-exec.go
docker run -d --name citi-h04b alpine:3 sleep 600
docker cp /tmp/memfd-exec citi-h04b:/tmp/memfd-exec

# audit: apply tracingpolicy.yaml → memfd_create event +
# process_exec with binary_properties.file.inode.links=0
./tetra tracingpolicy add citi-hypothesis/QCS-H04-fileless-exec/tracingpolicy.yaml
docker exec citi-h04b /tmp/memfd-exec        # prints CITI-H04-MEMFD-PAYLOAD-RAN

# enforce: apply tracingpolicy-block.yaml instead
./tetra tracingpolicy add citi-hypothesis/QCS-H04-fileless-exec/tracingpolicy-block.yaml
docker exec citi-h04b /tmp/memfd-exec        # rc=137, killed at memfd_create
