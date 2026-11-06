# QCS-H04 — Fileless or Inline Script Execution

## What we wanted to prove

If someone runs a script without ever saving it as a file — typing it into
the shell directly, or piping it in — does Qualys still see what it did?

## Verdict

**Partially — and the partial part matters (v1-verified on the cluster).**
You can't see the fileless script *itself*, but you see **everything it
does**: every command it launches, every file it opens, every connection
it makes, all attributed back to the shell that ran it. A file-based
script is the control: its binary field shows the script path, while
inline/stdin show only the interpreter.

**memfd fileless exec (the anonymous in-memory binary) is NOT covered in
this release IT shall be supported in the next release**.

## What we did (k8s flow, `hypo-run.py`)

- Applied `policy-v1.yaml` (file-open on the canary + `net-tcp-open`
  egress audit), waited for approval, ran `pod.yaml`, grepped the sensor
  logs for the detection payloads.
- `pod.yaml` runs four cases:
  - **Case 1:** `sh -c '...script...'` — script embedded in the command;
    also attempts an outbound connect (`curl` → :443)
  - **Case 2:** `sh` with the script fed in over standard input — nothing
    stored anywhere; same outbound connect
  - **Case 3 (E5 control):** a file-based script (`/tmp/citi-h04-file.sh`)
    — the launch record's binary is the script path

## What we observed (v1, live 2026-11-05)

| | Case 1: `sh -c` | Case 2: stdin | Case 3: file-based (control) |
|---|---|---|---|
| Interpreter seen | Yes — `/bin/sh` | Yes — `/bin/sh` | Yes — `/bin/sh` |
| Script content visible | **Yes** — the whole script is in the command line | **No** — launch record shows the shell with *no arguments* (in the pod form the heredoc text sits in the outer `sh -c` args — the clean "no-args" proof was the old `docker exec -i` form) | **No** — the script text is in the file, not the args |
| Binary field | interpreter (`sh`) | interpreter (`sh`) | **the script path** (`/tmp/citi-h04-file.sh`) |
| Child processes seen | Yes (`cat`, `sleep` — parent = the shell) | Yes (same) | Yes (same) |
| File it touched | Canary-open event recorded | Canary-open event recorded | Canary-open event recorded |
| Outbound connect | **Yes** — `Network Activity` payload (curl → :443), attributed to `citi-h04-egress-audit` | **Yes** — same | — (control: no egress) |

Evidence from the v1 run (windowed to the lab, PROVEN): `Process-exec
event payload` lines for the inline/stdin/file-backed execs, a `File event
payload` for the canary open, and the v1 policy lifecycle lines.

## Compared with the file-based scenario (case 3)

- A script **stored as a file** shows up by name — the launch record's
  binary is literally `/tmp/citi-h04-file.sh`.
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

## memfd fileless execution — next release

The anonymous in-memory binary (`memfd_create` + exec via
`/proc/self/fd/N`) was proven earlier with a raw Cilium TracingPolicy on
`sys_memfd_create` (audit: memfd-create event + `process_exec` with
`binary_properties.file.inode.links=0`; block: SIGKILL at create, rc=137).
**That form is not part of this release** — it cannot be expressed by
RuntimePolicy v1 or v2 today and the raw-TP policy files have been removed
from the lab. A future v2 `fileless`/`memfd` rule type (audit and block)
is the planned next-release path.

## Future implementation

- The interpreter launch record carries no payload for stdin-fed scripts.
  Capturing it would require hooking the interpreter's input read (e.g. a
  read of fd 0 at exec time) — no RuntimePolicy v2 field expresses that
  today.
- For memfd: a future v2 `fileless`/`memfd` rule type wrapping the
  `sys_memfd_create` hook (audit + block), and a `matchBinaries`
  extension that recognizes memory-backed bprm files to fix the
  block-by-path gap — **next release** items.

## Point-by-point check (original hypothesis)

| # | Execution point | Status | Evidence |
|---|---|---|---|
| E1 | Inline shell via `sh -c` | **YES** (live, v1) | `Process-exec event payload` — argv carries the **full inline script** |
| E2 | Script via standard input | **YES** (live, v1) | interpreter exec recorded; script body **not** visible (pod form: heredoc sits in the outer `sh -c` args) |
| E3 | Process, file-read, and network events from the inline script | **YES** (live, v1) | child `cat` → canary-open `File event payload`; `curl` → :443 `Network Activity` payload attributed to `citi-h04-egress-audit` |
| E4 | Interpreter, full command line, children, associated activity | **YES PARTIAL (file open)** | interpreter ✓; cmdline ✓ for `-c`, ✗ for stdin; children + file-open + network activity ✓ — matches the annotation |
| E5 | Compare with file-based script scenario | **YES** (live, v1) | case 3 in `pod.yaml`: file-based exec shows binary = `/tmp/citi-h04-file.sh` (script name visible); inline/stdin show only the interpreter |
| E6 | memfd fileless exec (audit + block) | **NOT COVERED — next release** | needs a raw `sys_memfd_create` TracingPolicy; raw-TP form removed from the lab (cannot apply in the k8s flow) |

**Not covered live:** E6 (memfd) — next-release item (see note above).

## eBPF-Agent events observed (2026-11-05 cluster runs, v1)

```json
// case 1 — inline `sh -c` (marker CITI-H04-inline)
{"process_exec":   {"process": {"binary": "/usr/bin/sh", "arguments": "-c \"echo CITI-H04-inline; cat /etc/citi-h04-canary.txt; sleep 1\""}}}
// case 2 — stdin-fed script (marker CITI-H04-stdin): interpreter only
{"process_exec":   {"process": {"binary": "/usr/bin/sh", "arguments": ""}}}
// case 3 — file-based script: binary IS the script path
{"process_exec":   {"process": {"binary": "/tmp/citi-h04-file.sh", "arguments": "/tmp/citi-h04-file.sh"}}}
// v1 policy payloads
{"File event payload": "canary open (citi-h04-canary-open, file-open)"}
{"Network Activity payload": "curl → :443, actor attributed to citi-h04-egress-audit"}
{"Process-exec event payload": "inline/stdin/file-backed execs, attributed to the shell"}
// memfd (next release): raw TracingPolicy on sys_memfd_create only
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy-v1.yaml` / `policy-v2.yaml` | canary-open + egress-audit rules |
| `pod.yaml` | pod running the fileless cases (1-2) + file-based control (3) |
| `RESULT.md` | this document |

Raw TracingPolicy forms (`tracingpolicy*.yaml`, `policy-memfd-block.yaml`)
were removed — memfd/fileless support is a **next-release** item.

EC2 verification (`hypo-run.py --labs 4`, v1 mode, 2026-11-06): **PROVEN** — 26 matching events.
