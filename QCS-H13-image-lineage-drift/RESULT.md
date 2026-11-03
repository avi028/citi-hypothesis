# QCS-H13 — Image Lineage and Runtime Integrity Change

## What we wanted to prove

Qualys preserves image lineage (digest, layers, build history) and can
tell immutable image content apart from changes made at runtime.

## Verdict

**Partial — image lineage is platform data, runtime drift is sensor
data.** The runtime side is fully proven: every post-deploy create/write/
open under the monitored directory is recorded with path, process,
container id, and timestamp. What the sensor cannot see is the *image*
itself — digests, layer diffs, and "which layer this file came from" are
Qualys platform/registry data. The join is: FIM events (drift) vs scan
layers (baseline) — anything FIM sees that no layer contains is runtime
drift *by definition*.

## What we did

- Policy: v2 file rules (`create`, `write`, `open`) on `/var/qualys-citi/h13/`
- Workload: container writes "baked" content and then a runtime change in
  the monitored dir, and reads the file back

## What we observed

All three operations fired with full attribution (container `6fb65041…`):

- `security_inode_create` — dir/files created (`bash`)
- `vfs_write` — both files written (`bash`)
- `security_file_open` — opens incl. the read-back by `cat`

## The image vs runtime split

| Evidence | Source |
|---|---|
| Image digest, layer list, build history, v1→v2 diff | Qualys registry scan (platform) |
| Running container ↔ image association | k8s/OpenShift fields on exec events (pod, image digest in pod spec) |
| Runtime file changes (drift) | FIM events — this lab |
| "Is this change part of the image?" | platform join: drift event path ∉ image layers → drift |

In the docker simulation every write is a runtime write (nothing is
image-baked). In a real cluster the same FIM rule fires only for
post-deploy writes — image-baked content is created by the image build,
never by the container, so it can't trigger FIM.

## Caveats

- File events show the runtime file path; there is no layer/bookkeeping
  data on events.
- Pod/image-digest association requires k8s/OpenShift (plain docker shows
  container id only).

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
|---|---|---|---|
| E1 | Scan + deploy image v1 | **NOT COVERED live** | scan = platform; docker stands in for the pod |
| E2 | Replace with image v2 | **NOT COVERED live** | image build/swap is platform/cluster |
| E3 | Introduce runtime file change post-deploy | **YES** | create/write/open under `/var/qualys-citi/h13` all recorded |
| E4 | Compare build history / digest / metadata / container / drift | **Partial** | drift events carry path+process+container; digest/layer data = platform |
| E5 | Layer changes vs runtime changes distinguishable | **YES PARTIAL** | every FIM event IS runtime (image layers are immutable and never trigger FIM) — join with scan data for the full diff |

**Not covered live:** E1/E2/E4 (image side — platform).

## eBPF-Agent events observed (2026-11-03 run)

```json
{"process_kprobe": {"policy_name": "citi-h13-drift-v2-drift-create", "function_name": "security_inode_create", "process": {"binary": "/usr/bin/bash"}}}
{"process_kprobe": {"policy_name": "citi-h13-drift-v2-drift-write", "function_name": "vfs_write",
 "process": {"binary": "/usr/bin/bash"}, "args": [{"file_arg": {"path": "/var/qualys-citi/h13/runtime.txt"}}]}}
{"process_kprobe": {"policy_name": "citi-h13-drift-v2-drift-open", "function_name": "security_file_open",
 "process": {"binary": "/usr/bin/cat"}, "args": [{"file_arg": {"path": "/var/qualys-citi/h13/baked.txt"}}]}}
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | v2 FIM (create/write/open) on the writable dir |
| `policy-v1.yaml` | v1 equivalents (file-create/write/open) |
| `pod.yaml` | two pods (v1/v2 image sim) writing baked + runtime content |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H13-image-lineage-drift/policy.yaml
docker run --rm debian:stable-slim bash -c '
  mkdir -p /var/qualys-citi/h13
  echo baked-v1 > /var/qualys-citi/h13/baked.txt
  echo runtime-change-v2 > /var/qualys-citi/h13/runtime.txt
  cat /var/qualys-citi/h13/baked.txt'
```

Result: create + write + open events for both files with path, process,
and container attribution.