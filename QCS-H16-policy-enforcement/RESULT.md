# QCS-H16 — Runtime Policy Enforcement / Process Blocking

## What we wanted to prove

Qualys can move from audit-only monitoring to actually stopping a process
that violates a runtime policy — and the pod keeps running throughout.

## Verdict

**Covered: enforcement at the process and file level.** The same rule in
audit mode logged the probe execution and let it run; switched to
`block`, the probe was **killed at exec** (SIGKILL) while the pod
continued to run normally. Filesystem-write blocking is proven in QCS-H02
the same way.

**Not covered (platform):** pod network deactivation, memory dumps, pod
termination, and image blocklisting are Qualys **platform response
actions** — not runtime-sensor capabilities. The runtime sensor's
contribution is enforcement at the process/file hook level.

## What we did

- Probe: harmless script in `/tmp`
- Policy: process rule on the probe — audit mode first, then the same
  rule with `action: block` (cluster runs)

## What we observed

| Phase | Probe result | Pod stability |
| --- | --- | --- |
| audit | ran, rc=0 | still alive |
| enforce | killed at exec, rc=137 | still alive |

EC2 run (`hypo-run.py --labs 16`, v1 mode, 2026-11-06): **PROVEN** —
6 events in 74s. The v1 `file-open` + `action: kill` policy on the probe
script **enforced**: the opener was SIGKILLed and the pod went unready —
the documented v1 enforcement shape (kill-on-open kills the accessor;
the cleaner exec-block that keeps the pod stable is the v2 process rule,
untestable here since this cluster's CRD serves v1 only).

## Caveats

- `action: block` = SIGKILL at the hook (exit 137), not a clean
  "permission denied".
- Keep block policies narrow (namespace/workload scoping) to avoid
  killing legitimate traffic.
- v1 has no process-exec base-policy — the exec-block leg is v2-only
  (v1 `action: kill` covers file operations only).

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Audit mode: detection without interruption | **YES** | probe ran (rc=0), event posted |
| E2 | Enable enforcement (same scoped policy) | **YES** | block variant loaded |
| E3 | Re-execute the process | **YES** | probe killed at exec — rc=137 |
| E4 | Launch blocked or process terminated? | **YES** | SIGKILL at exec — the exec is stopped before it commits |
| E5 | Pod stability + enforcement telemetry | **YES** | container stayed alive after the kill; the kill is recorded |
| E6 | Net deactivation / memdump / pod kill / image blocklist | **NOT COVERED (platform)** | Qualys platform response actions |

**Not covered live:** E6 (platform response menu).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | audit + enforce variants of the process rule (v1: file-open kill approximation) |
| `pod.yaml` | disposable pod dropping + running the probe |
| `RESULT.md` | this document |
