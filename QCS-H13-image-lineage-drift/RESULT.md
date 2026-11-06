# QCS-H13 — Image Lineage and Runtime Integrity Change

## What we wanted to prove

Qualys preserves image lineage (digest, layers, build history) and can
tell immutable image content apart from changes made at runtime.

## Verdict

**Partial — image lineage is platform data, runtime drift is covered.**
The runtime side is fully covered: every post-deploy create/write/open
under the monitored directory is recorded with path, process, container,
and timestamp. What the sensor cannot see is the *image* itself — digests,
layer diffs, and "which layer this file came from" are Qualys
platform/registry data. The join: runtime events (drift) vs scan layers
(baseline) — anything the runtime sees that no layer contains is runtime
drift *by definition*.

## What we did

- Policy: file rules (create/write/open) on the monitored directory
- Workload (cluster): a pod writes "baked" content and then a runtime
  change in the monitored dir, and reads the file back

## What we observed

All three operations fired with full attribution:

- create — dir/files created
- write — both files written
- open — including the read-back

## The image vs runtime split

| Evidence | Source |
| --- | --- |
| Image digest, layers, build history, v1→v2 diff | Qualys registry scan (platform) |
| Running container ↔ image association | k8s/OpenShift fields on events |
| Runtime file changes (drift) | runtime events — this lab |
| "Is this change part of the image?" | platform join: drift path not in image layers → drift |

In a real cluster the same file rules fire only for post-deploy writes —
image-baked content is created by the image build, never by the
container, so it cannot trigger them.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Scan + deploy image v1 | **NOT COVERED live** | scan = platform |
| E2 | Replace with image v2 | **NOT COVERED live** | image build/swap is platform/cluster |
| E3 | Introduce runtime file change post-deploy | **YES** | create/write/open under the monitored dir all recorded |
| E4 | Compare build history / digest / metadata / container / drift | **Partial** | drift events carry path + process + container; digest/layer data = platform |
| E5 | Layer changes vs runtime changes distinguishable | **YES PARTIAL** | every runtime event IS drift (image layers are immutable and never trigger them) — join with scan data for the full diff |

**Not covered live:** E1/E2/E4 (image side — platform).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | file rules (create/write/open) on the writable dir |
| `pod.yaml` | pods writing baked + runtime content |
| `RESULT.md` | this document |