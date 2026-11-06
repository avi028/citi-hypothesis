# QCS-H17 — Deleted Pod Historical Activity and Event Retention

## What we wanted to prove

After a pod and its container no longer exist, is the runtime evidence of
what it did still available and searchable?

## Verdict

**Covered.** A short-lived workload ran a file + process + network
sequence, was deleted, and its events **remained in the event stream**,
searchable by the recorded container id and by a unique marker in the
command line. Retention *duration* is a platform setting (e.g. a 7-day
window) — the sensor itself does not delete evidence with the pod.

## What we did

- Policy: file-open rule on a payload path + egress rule on the receiver
  port
- Workload (cluster): wrote a payload file, read it, connected to the
  internal endpoint, then the pod was removed

## What we observed

- Container id recorded **before** deletion.
- After deletion: the events for that container remain — exec/exit of the
  involved processes (base stream) + the policy events (payload-open by
  the reader, egress to the receiver port).
- The payload marker is also searchable — events were recovered by marker
  even after the container id lookup.

EC2 run (`hypo-run.py --labs 17`, v1 mode, 2026-11-06): **PROVEN** —
30 matching events in 19.4s for the short-lived Job's file + exec +
network sequence (the Job's wget now hits a real `citi-h17-svc` receiver
shipped in `pod.yaml` — previously the name didn't resolve, so the
network leg produced no event).

## What "retention" means where

| Ask | Where it works |
| --- | --- |
| Events survive pod deletion | Yes — this lab (the sensor exports events independently of the pod) |
| Search by pod UID / container id / image digest | Container id proven; pod UID/image digest fields populate under k8s |
| How long events are kept | Platform retention setting (e.g. 7 days) — not a sensor property |
| Full activity reconstruction | Yes — exec/exit + policy events join by the process chain + container id |

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Known file/process/network sequence | **YES** | payload write+read + connect to the receiver |
| E2 | Record workload identifiers | **YES** | container id captured pre-delete |
| E3 | Delete pod / let Job complete | **YES** | pod removed |
| E4 | Search by deleted identifiers | **YES** | events for the deleted container remain, policy-matched |
| E5 | Evidence remains + activity reconstructible | **YES** | exec/exit + policy events join by process chain + container id |

**Not covered live:** none (retention *window* = platform setting).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | payload-open + egress rules that tag the evidence |
| `pod.yaml` | short-lived workload (file + process + network burst, auto-removed) |
| `RESULT.md` | this document |