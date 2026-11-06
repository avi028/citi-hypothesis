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
- Workload (cluster, fully automated): `pod.yaml` runs the whole
  allow → deny → retry sequence itself. The toolbox pod waits for the
  service, curls it (baseline — allowed by `allow-citi-h07-client`),
  deletes that NetworkPolicy via the K8s API using its own ServiceAccount
  (Role scoped to `delete networkpolicies` in `citi-h07-target`), then
  repeats the same curl under `default-deny-citi-h07` and keeps
  attempting every 15s. Both NetworkPolicy documents are applied
  together — ingress rules are unioned, so the flow is allowed until the
  allow policy is deleted.

## What we observed

Client side (toolbox pod log, k8s run on EC2, CNI enforces NetworkPolicy):

```text
CITI-H07: waiting for target service
CITI-H07 baseline connect (allowed)
baseline rc=0 http=403
CITI-H07 deleting allow-citi-h07-client
{ "kind": "Status", "status": "Success",
  "details": { "name": "allow-citi-h07-client",
               "kind": "networkpolicies" } }
CITI-H07 denied connect (default-deny)
denied rc=28        <- curl timeout: the deny really blocked the flow
```

Sensor side (`qualys-runtime-sensor` logs, policy `citi-h07-netpol-denied`):

| Attempt | Client outcome | Event recorded? |
| --- | --- | --- |
| Baseline curl → `citi-h07-svc:8080` | rc=0 (connected; httpd answered 403) | Yes — `Network Activity` event, `/usr/bin/curl`, parent `/usr/bin/sh` (the script), pod `citi-h07-toolbox`, ns `citi-h07-client`, dst `10.96.251.81:8080` |
| Same curl after the allow policy was deleted | rc=28 — timed out, denied | Yes — **identical event**, same dst IP:port, same attribution |
| 15s retry loop (still denied) | rc=28 each time | Yes — one event per attempt |

Both events carry `"disposition": "Allowed"` / `"status": "Success"` —
those fields describe the sensor's kprobe action (the event was posted),
not the network outcome. The attempt lands in the stream at SYN-send;
the drop happens afterwards and does not erase it.

Also observed: ambient cluster traffic to :8080 (e.g. coredns →
`127.0.0.1:8080`) matched the same policy — the rule is cluster-wide,
not pod-scoped.

`hypo-run.py --labs 7` (v1 mode, k8s backend, 2026-11-06): **PROVEN** —
34 matching events (10 policy hits, 24 activity/process_exec) in 53.1s.

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
| S2 | Target service with default-deny NetworkPolicy | **YES** (cluster) | real `default-deny-citi-h07` NetworkPolicy — swapped in by the workload itself via API delete of the allow policy; enforcement confirmed by client rc=28 |
| S5 | OpenShift network evidence for corroboration | **NOT COVERED live** | platform leg |
| E1 | Connect while allowed | **YES** | `Network Activity`/`tcp_connect` event (client rc=0) |
| E2 | Apply default-deny | **YES** | toolbox deleted `allow-citi-h07-client` via the K8s API (SA + Role) — `Status: Success` |
| E3 | Repeat the connection | **YES** | client timed out (rc=28) but `tcp_connect` **still recorded** |
| E4 | Compare successful vs blocked telemetry | **YES** | events are **identical** — attempt recorded, outcome not |
| E5 | Attempt / success / no event? | **YES** | Qualys reports the attempt (H06/H07 pattern confirmed) |

**Not covered live:** S5 (OpenShift network logs — platform). On a CNI
that does not enforce NetworkPolicy the denied curl still connects —
the event is recorded either way, since `tcp_connect` fires at the
attempt.

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | egress audit on the service port |
| `pod.yaml` | client + target namespaces, service, allow/deny NetworkPolicies, and a toolbox pod (+ SA/Role/RoleBinding) that runs the whole allowed → denied sequence automatically |
| `RESULT.md` | this document |
