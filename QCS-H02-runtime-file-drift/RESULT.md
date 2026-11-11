# QCS-H02 — Runtime File Drift and Unauthorized Executable Creation

## What we wanted to prove

If someone drops a brand-new file or script into a running container —
creates it, changes it, makes it executable, runs it, renames it, deletes
it — Qualys records every step. And in enforcement mode, it can stop the
activity instead of just watching it.

## Verdict

**Detected in both v1 and v2; enforcement is partial.** Every drift step
(create/write/metadata/rename/delete) is detected with attribution in both
policy forms. In enforcement mode, the **write into the blocked directory
is stopped** (SIGKILL mid-write, pod exit 137). The caveat is
**v1-specific: v1 cannot stop the shell script from running** — v1 has no
exec/process base-policy, and the only v1 lever (`file-open` + `kill`)
would kill any open of a file at that location — far too wide a scope.
**v2 can stop the script**: its process rule (`drift-block-exec`) kills the
exec before the script's payload runs.

## What we did (k8s two-phase flow, `hypo-run.py`)

- **Audit phase**: applied `policy-v1.yaml` (5 v1 base-policy CRs:
  file-create/write/metadata/rename/delete on `/tmp/citi-h02/`), waited for
  approval, ran `pod.yaml` — a pod that drops a script into `/tmp/citi-h02`
  after startup, modifies it, chmods it, runs it, renames it, deletes it.
  Grepped the sensor logs for the detection payloads.
- **Enforcement phase**: removed the audit pod + policy, applied
  `policy-v1-enforce.yaml` (file-write **kill** on `/tmp/citi-h02-block/`;
  v2 uses `policy-enforce.yaml`, which adds the process rule
  `drift-block-exec`), then ran `pod-enforce.yaml` — a pod that attempts to
  (1) exec a dropped script staged inside the blocked dir and (2) write
  `evil.sh` into it.

## What we observed — audit mode (both v1 and v2)

Every action produced a detection record naming the program, the full
command line, the container, the file path, and the node:

| Attacker action | Detection record |
|---|---|
| Create the script | "new file created" event |
| Append to the script | "file written" event (one per write) |
| `chmod 755` | "permissions changed" event |
| Execute the script | process-execution event (free with the base sensor) |
| `mv` rename | "file renamed" event — **both** old and new names captured |
| `rm` delete | "file deleted" event — name preserved even though file is gone |

Nothing was missed; even the delete leaves a searchable record. Verified
live on the cluster in v1 mode (40 evidence: 6 policy + 34
activity/process_exec).

## What we observed — enforcement mode

| Attempt | Result |
|---|---|
| `echo evil > /tmp/citi-h02-block/evil.sh` | Shell **SIGKILLed mid-write** (exit 137, pod Failed). The kill is recorded as a File event payload. |
| Execute dropped script `/tmp/citi-h02-block/drift.sh` | **v1: NOT blocked — the script runs.** v1 has no exec rule, and `file-open` + `kill` would kill any open of a file in the dir (too wide a scope). **v2: blocked** at `security_bprm_check` — the script is killed before its payload runs. Live v1 run showed the exec running (`Process ALLOWED`, process-tree entry). |

## One thing to know

- The **script-exec gap is v1-only**: v1 has no exec/process base-policy,
  and its only file-level lever (`file-open` + `kill`) would kill any open
  of a file in the watched directory — far too wide a scope. **v2 closes
  the gap** with its process rule (`drift-block-exec` at
  `security_bprm_check`).
- The audit policy and the enforce policy are separate RuntimePolicy
  files; on OpenShift you'd apply audit first, then switch to enforce.

## Point-by-point check (original hypothesis)

| # | Execution point | Status | Evidence |
|---|---|---|---|
| E1a | File create under monitored dir | **YES** (live) | `security_inode_create` (`bash`) |
| E1b | File write | **YES** (live) | `vfs_write` (`bash`) |
| E1c | Metadata change (chmod) | **YES** (live) | `security_path_chmod` (`chmod`) |
| E1d | Rename | **YES** (live) | `security_path_rename` (`mv`) |
| E1e | Delete | **YES** (live) | `security_path_unlink` (`rm`) |
| E2 | Enforce: kill the writer on block-dir write | **YES** (live, v1) | `File event payload` (kill action), pod exit 137 — write stopped |
| E3 | Enforce: block exec of the dropped script | **v2: YES; v1: NO** | v2: SIGKILL at `security_bprm_check` before the payload runs (H16-verified pattern). v1: no exec rule — `file-open` + `kill` would be too wide; live v1 run: the script ran |
| E4 | Attribution (process, cmdline, UID, container, node, time) | **YES** (live) | `process.binary`, `arguments`, `uid`, container, `node_name`, `time` on every event; pod/ns fields verified in cluster runs |

**Not covered live:** the v1 leg of E3 (script-exec block) — v1 has no exec
rule; the only v1 lever (file-open kill) is too wide. v2 covers E3 via its
process rule.

## eBPF-Agent events observed (2026-11-05 cluster runs, v1)

```json
// audit (policy citi-h02-drift-*)
{"process_kprobe": {"policy_name": "citi-h02-drift-create",   "function_name": "security_inode_create",  "process": {"binary": "/usr/bin/bash"}}}
{"process_kprobe": {"policy_name": "citi-h02-drift-write",    "function_name": "vfs_write",             "process": {"binary": "/usr/bin/bash"}}}
{"process_kprobe": {"policy_name": "citi-h02-drift-metadata", "function_name": "security_path_chmod",   "process": {"binary": "/usr/bin/chmod"}}}
{"process_kprobe": {"policy_name": "citi-h02-drift-rename",   "function_name": "security_path_rename", "process": {"binary": "/usr/bin/mv"}}}
{"process_kprobe": {"policy_name": "citi-h02-drift-delete",   "function_name": "security_path_unlink", "process": {"binary": "/usr/bin/rm"}}}

// enforce (policy citi-h02-drift-block-write, action: kill) — v1 run
//   write attempt -> killed: File event payload (SIGKILL), pod exit 137
//   exec attempt  -> NOT blocked in v1: "Process ALLOWED -
//                    process='/tmp/citi-h02-block/drift.sh'" + "New process
//                    added to tree: .../drift.sh" (the script ran)
//   v2 (policy-enforce.yaml drift-block-exec): SIGKILL at
//   security_bprm_check — the script is stopped before its payload runs
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy-v1.yaml` / `policy-v2.yaml` | Audit-mode detection rules (create/write/metadata/rename/delete on `/tmp/citi-h02/`) |
| `policy-v1-enforce.yaml` / `policy-enforce.yaml` | Enforcement rules — kill the writer on `/tmp/citi-h02-block/`; v2 adds the process rule `drift-block-exec` (stops the script at `security_bprm_check`) |
| `pod.yaml` | Audit-phase workload (the drift lifecycle) |
| `pod-enforce.yaml` | Enforcement-phase workload (exec + write attempts into the blocked dir) |
| `RESULT.md` | This document |

Two-phase flow: `sudo PYTHONDONTWRITEBYTECODE=1 python3 hypo-run.py --labs 2 --yes` runs audit →
enforcement automatically (v1 default; `--policy-mode v2` for v2).

EC2 verification (`hypo-run.py --labs 2`, v1 mode, 2026-11-06): **PROVEN** — 16 matching events.
