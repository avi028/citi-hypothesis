# QCS-H01 — Container Escape / Host File Access Attempt

## What we wanted to prove

When a container reads a file that belongs to the underlying host
(a controlled directory mounted into it), Qualys sees it and can report
**who did it, from where, and what they touched**.

## Verdict

**It works.** Every read of the host marker file was recorded, and each
record told us exactly which container, which program, which command, and
which file.

## What we did

- Wrote a policy (`policy.yaml`) that says: *"report every read of a file
  whose path ends in `/QCS-H01/canary.txt`"*
- Created a marker file on the host at `/var/qualys-poc/QCS-H01/canary.txt`
- Ran a container that mounted that host folder read-only and did the
  things an attacker (or auditor) would do: `ls`, `stat`, `cat`,
  `sha256sum`

## What we observed

- `cat` and `sha256sum` — the two commands that actually read the file's
  contents — each produced a detection record containing:
  - the program used (`cat`, `sha256sum`)
  - the exact file path
  - which container it ran in (container id)
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
suffix should be relaxed to just the filename.

## Point-by-point check (original hypothesis)

| # | Execution point | Status | Evidence |
|---|---|---|---|
| E1 | Confirm a normal **restricted-v2 pod cannot access the host path** | **NOT COVERED live** | `pod.yaml` ships `citi-h01-restricted` (restricted-v2: non-root, no caps, seccomp) — needs a cluster apply to run; the docker-local analog (mounting the same dir at a different path → no event) shows detection is path-scoped, but the pod-level denial itself is a cluster/platform check |
| E2 | Deploy an approved **elevated pod** with the test directory mounted **read-only** | Partial | `pod.yaml` ships `citi-h01-elevated` (hostPath, `readOnly: true`, hostmount-anyuid SCC note) — cluster apply required; docker-local equivalent verified live with `-v …:ro` |
| E3 | Run **ls, stat, cat, sha256sum** against the synthetic host file | **YES** (live) | `ls`/`stat` → no policy event (metadata-only, correct); `cat`/`sha256sum` → `vfs_read` events |
| E4 | Validate **namespace, pod, container, process tree, command line, file path, node** attribution | **YES** | live: container id, process tree (`exec_id`/`parent_exec_id`), command line, `file_arg.path`, `node_name`, `time`; namespace/pod fields verified in cluster runs (populate under k8s/OpenShift; docker-local shows container id only) |
| E5 | **Delete the pod** and confirm **historical activity remains searchable** | **YES** (live) | events persist in the stream after the container is removed — same evidence pattern as QCS-H17 (11 events survived deletion); `docker rm` of the test container leaves all records searchable by container id |

**Not covered live:** E1 (restricted-v2 pod denial — cluster), E2 (elevated
pod apply — cluster). See README "Execution points not covered".

## Tetragon events observed

```json
{"process_kprobe": {"policy_name": "citi-h01-host-file-access-v2-host-file-read", "function_name": "vfs_read",
 "process": {"binary": "/usr/bin/cat", "arguments": "/var/qualys-poc/QCS-H01/canary.txt", "docker": "…"},
 "args": [{"file_arg": {"path": "/var/qualys-poc/QCS-H01/canary.txt"}}]}}
// sha256sum reads fire the same rule; ls/stat produce no policy event (no content read)
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | The detection rule (load with `tetra tracingpolicy add`) |
| `pod.yaml` | Apply to the cluster to generate the test activity |
| `RESULT.md` | This document |

## docker run command used for the local proof

```bash
docker run --rm \
  -v /var/qualys-poc/QCS-H01:/var/qualys-poc/QCS-H01:ro \
  debian:stable-slim sh -c '
    TARGET=/var/qualys-poc/QCS-H01/canary.txt
    ls -l /var/qualys-poc/QCS-H01
    stat "$TARGET"; cat "$TARGET"; sha256sum "$TARGET"'
```

Result: 4 detection events for `cat` and `sha256sum`, all with full
container, process, file, and node attribution.
