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
is stopped** (SIGKILL mid-write, pod exit 137). The **one caveat in both
v1 and v2: the sensor cannot stop the shell script from running** — the
exec of the dropped script is not blocked (v1 has no exec rule at all;
v2's exec-block rule does not stop the script from running), so the
script's payload executes.

## What we did (k8s two-phase flow, `hypo-run.py`)

- **Audit phase**: applied `policy-v1.yaml` (5 v1 base-policy CRs:
  file-create/write/metadata/rename/delete on `/tmp/citi-h02/`), waited for
  approval, ran `pod.yaml` — a pod that drops a script into `/tmp/citi-h02`
  after startup, modifies it, chmods it, runs it, renames it, deletes it.
  Grepped the sensor logs for the detection payloads.
- **Enforcement phase**: removed the audit pod + policy, applied
  `policy-v1-enforce.yaml` (file-write **kill** on `/tmp/citi-h02-block/`),
  then ran `pod-enforce.yaml` — a pod that attempts to (1) exec a dropped
  script staged inside the blocked dir and (2) write `evil.sh` into it.

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
| Execute dropped script `/tmp/citi-h02-block/drift.sh` | **NOT blocked — the script runs.** The sensor cannot stop the shell script from executing; the exec is visible in the base process stream (`Process ALLOWED`, process-tree entry) but no exec rule stops it. **Caveat in both v1 and v2.** |

## One thing to know

- "Block" means the offending **process is terminated** (SIGKILL) at the
  moment it touches the watched path — it is not a clean "permission
  denied", the actor dies. That's the intended behavior for enforcement.
- The **script-exec leg is the gap**: v1 has no exec/process base-policy at
  all, and the v2 process rule does not stop the shell script from running.
  Only the file-write leg is actually enforced.
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
| E3 | Enforce: block exec of the dropped script | **NO — caveat** | the script **runs**; the sensor cannot stop the shell script from executing (v1: no exec rule; v2: exec-block does not stop it) |
| E4 | Attribution (process, cmdline, UID, container, node, time) | **YES** (live) | `process.binary`, `arguments`, `uid`, container, `node_name`, `time` on every event; pod/ns fields verified in cluster runs |

**Not covered live:** E3 (script-exec block) — the caveat in both v1 and v2.

## eBPF-Agent events observed (2026-11-05 cluster runs, v1)

```json
// audit (policy citi-h02-drift-*)
{"process_kprobe": {"policy_name": "citi-h02-drift-create",   "function_name": "security_inode_create",  "process": {"binary": "/usr/bin/bash"}}}
{"process_kprobe": {"policy_name": "citi-h02-drift-write",    "function_name": "vfs_write",             "process": {"binary": "/usr/bin/bash"}}}
{"process_kprobe": {"policy_name": "citi-h02-drift-metadata", "function_name": "security_path_chmod",   "process": {"binary": "/usr/bin/chmod"}}}
{"process_kprobe": {"policy_name": "citi-h02-drift-rename",   "function_name": "security_path_rename", "process": {"binary": "/usr/bin/mv"}}}
{"process_kprobe": {"policy_name": "citi-h02-drift-delete",   "function_name": "security_path_unlink", "process": {"binary": "/usr/bin/rm"}}}

// enforce (policy citi-h02-drift-block-write, action: kill)
//   write attempt -> killed: File event payload (SIGKILL), pod exit 137
//   exec attempt  -> NOT blocked: "Process ALLOWED - Regex match: process='/tmp/citi-h02-block/drift.sh'"
//                    + "New process added to tree: /tmp/citi-h02-block/drift.sh" (the script ran)
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy-v1.yaml` / `policy-v2.yaml` | Audit-mode detection rules (create/write/metadata/rename/delete on `/tmp/citi-h02/`) |
| `policy-v1-enforce.yaml` / `policy-enforce.yaml` | Enforcement rules — kill the writer on `/tmp/citi-h02-block/` (v2 also carries an exec-block rule that does not stop the script) |
| `pod.yaml` | Audit-phase workload (the drift lifecycle) |
| `pod-enforce.yaml` | Enforcement-phase workload (exec + write attempts into the blocked dir) |
| `RESULT.md` | This document |

Two-phase flow: `sudo python3 hypo-run.py --labs 2 --yes` runs audit →
enforcement automatically (v1 default; `--policy-mode v2` for v2).
