# QCS-H07 — Network Policy Violation and Denied Connection Attempt

## What we wanted to prove

When the platform (NetworkPolicy / firewall) blocks a connection, does
Qualys still record the attempt — or only successful connections?

## Verdict

**Covered now: the attempt is recorded, always.** Qualys sees the
connection the moment it is initiated — before the platform drops it — so
denied flows produce the same event as allowed ones. Whether it succeeded
must be corroborated with platform evidence (OpenShift network/audit
logs), not from the event alone.

## What we did

- Policy: audit outbound TCP to port 8080
- Workload (cluster): connected successfully (baseline), then repeated the
  same connect under a simulated default-deny (firewall DROP) — which
  timed out at the client

## What we observed

| Attempt | Outcome | Event recorded? |
| --- | --- | --- |
| Baseline connect | Succeeded | Yes — src/dst/port/process |
| Same connect under the DROP rule | Timed out — denied | Yes — identical record |

Both events are the same shape: the attempt lands in the stream at
SYN-send; the refusal/drop happens afterwards and does not erase it.

## Why this is valuable — and what it can't tell you

- **Valuable**: a denied exfiltration or lateral-movement attempt still
  leaves forensic evidence — who tried, where to, when. The platform
  silently dropping the packet does not hide the attempt.
- **Limit**: the event reads the same for success and denial, so "did it
  get through" needs the OpenShift network/audit logs alongside. Qualys =
  attempt telemetry; platform logs = verdict telemetry. Together they
  answer both questions.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| S2 | Target service with default-deny NetworkPolicy | **NOT COVERED live** | needs OpenShift — simulated with a firewall DROP |
| S5 | OpenShift network evidence for corroboration | **NOT COVERED live** | platform leg |
| E1 | Connect while allowed | **YES** | `tcp_connect` event (client rc=0) |
| E2 | Apply default-deny (firewall DROP) | **YES** (sim) | DROP rule on the path |
| E3 | Repeat the connection | **YES** | client blocked but `tcp_connect` **still recorded** |
| E4 | Compare successful vs blocked telemetry | **YES** | events are **identical** — attempt recorded, outcome not |
| E5 | Attempt / success / no event? | **YES** | Qualys reports the attempt (H06/H07 pattern confirmed) |

**Not covered live:** S2/S5 (real NetworkPolicy + OpenShift logs —
platform).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | egress audit on the service port |
| `pod.yaml` | client + target namespaces + allow/default-deny NetworkPolicies |
| `RESULT.md` | this document |