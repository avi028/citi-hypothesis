# QCS-H01 — Container Escape / Host File Access Attempt

## What we wanted to prove

When a container reads a file that belongs to the underlying host
(a controlled directory mounted into it), Qualys sees it and can report
**who did it, from where, and what they touched**.

## Verdict

**Requires RuntimePolicy v2 — not v1.** The hypothesis targets a specific
host file (`…/QCS-H01/canary.txt`), which is expressed with the `Postfix`
path operator in `policy-v2.yaml`. **v1 cannot express this lab**: v1
`monitor-paths` are matched as a **Prefix** of the resolved path only —
there is **no Postfix** in v1 — so v1 cannot determine the host file. A v1
prefix on the mount directory would over-match (every file under the
directory, and it breaks if the mount point differs) and cannot scope to
the canary itself. In v1 mode this lab is **NOT supported** — the runner
reports `not supported in v1` rather than silently switching to v2
(run `--policy-mode v2` to execute it).

## What we did

- Wrote a policy (`policy-v2.yaml`) that says: *"report every read of a file
  whose path ends in `/QCS-H01/canary.txt`"* (v2 `Postfix` operator)
- Created a marker file on the host at `/var/qualys-poc/QCS-H01/canary.txt`
- Applied the pod on the cluster: it mounts that host folder read-only and
  does the things an attacker (or auditor) would do: `ls`, `stat`, `cat`,
  `sha256sum`

## What we observed

- `cat` and `sha256sum` — the two commands that actually read the file's
  contents — each produced a detection record containing:
  - the program used (`cat`, `sha256sum`)
  - the exact file path
  - which namespace/pod/container it ran in
  - the full command that launched it, including its parent shell
  - the host (node) it happened on and the exact time
- `ls` and `stat` did not trigger a detection — correct behavior, since
  neither actually reads the file's contents. They still show up in normal
  process activity logs.
- Deleting the test setup does not remove history — the records are
  already captured in the event stream.

## One thing to know for the real deployment

The detection matches the file path **as the container sees it**. When we
mounted the same host folder at a different path (`/mnt/poc` instead of
`/var/qualys-poc/QCS-H01`), the reads were not flagged. So on OpenShift,
the `hostPath` in `pod.yaml` should be mounted at the same location the
policy expects — exactly as written in the manifest — or the policy's path
suffix (the v2 `Postfix`) should be relaxed to just the filename.

## Point-by-point check (original hypothesis)

| # | Execution point | Status | Evidence |
|---|---|---|---|
| E1 | Confirm a normal **restricted-v2 pod cannot access the host path** | **NOT COVERED live** | `pod.yaml` ships `citi-h01-restricted` (restricted-v2: non-root, no caps, seccomp). On the cluster it cannot start (`CreateContainerConfigError`) — the denial happens at admission/pod-creation; a path-level access denial was not demonstrated |
| E2 | Deploy an approved **elevated pod** with the test directory mounted **read-only** | **YES** (cluster) | `citi-h01-elevated` applied on the cluster (hostPath, `readOnly: true`); its reads produced the detection events |
| E3 | Run **ls, stat, cat, sha256sum** against the synthetic host file | **YES** (live) | `ls`/`stat` → no policy event (metadata-only, correct); `cat`/`sha256sum` → `vfs_read` events |
| E4 | Validate **namespace, pod, container, process tree, command line, file path, node** attribution | **YES** | cluster runs: namespace, pod, container id, process tree (`exec_id`/`parent_exec_id`), command line, `file_arg.path`, node, time all populated on the events |
| E5 | **Delete the pod** and confirm **historical activity remains searchable** | **YES** (live) | events persist in the stream after the pod is removed — same evidence pattern as QCS-H17 (11 events survived deletion); all records searchable by container id |

**Not covered live:** E1 (restricted-v2 pod denial — admission/platform).
See README "Execution points not covered".

## eBPF-Agent events observed

```json
{"process_kprobe": {"policy_name": "citi-h01-host-file-access-v2-host-file-read", "function_name": "vfs_read",
 "process": {"binary": "/usr/bin/cat", "arguments": "/var/qualys-poc/QCS-H01/canary.txt",
             "pod": "citi-h01-elevated", "namespace": "citi-h01"},
 "args": [{"file_arg": {"path": "/var/qualys-poc/QCS-H01/canary.txt"}}]}}
// sha256sum reads fire the same rule; ls/stat produce no policy event (no content read)
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy-v2.yaml` | The detection rule (v2; `Postfix` on the canary path) |
| `pod.yaml` | Apply to the cluster to generate the test activity |
| `RESULT.md` | This document |

No `policy-v1.yaml` — v1 has no Postfix and **cannot express this lab**;
v1 runs report `not supported in v1` (same pattern as QCS-H20) — use
`--policy-mode v2`.
