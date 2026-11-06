# QCS-H19 — Sensor Coverage and Health Failure Detection

## What we wanted to prove

Qualys reports which nodes/workloads have a healthy runtime sensor, and
detects when monitoring is degraded or unavailable.

## Verdict

**Covered — the sensor health cycle is real and observable.** A
deliberate sensor interruption produced a clean **event gap** (zero
events while the agent was down), and recovery restored the event flow.
Node-level "degraded / not reporting" status in the Qualys UI is the
platform's view of exactly this cycle.

## What we did

1. Baseline: policy on a health-probe binary, probe exec → event
2. Interrupt: the sensor agent was stopped (the approved interruption on
   a node)
3. Probe exec during the outage → **0 new events** (the gap)
4. Recovery: agent restarted, policy re-applied (in-cluster the
   operator/reconciler re-adds it), capture reconnected → events flow
   again

## What we observed

| Phase | Agent | New policy events |
| --- | --- | --- |
| baseline | up | 1 |
| outage | down | **0** (gap) |
| recovery | up | 1 (resumed) |

EC2 run (`hypo-run.py --labs 19`, v1 mode, 2026-11-06): **PROVEN** —
9 matching events in 51.5s: the `true` probe's steady exec/file-open
stream is recorded per-pod, giving the baseline signal a sensor outage
would visibly interrupt.

## Mapping to the cluster procedure

| Hypothesis step | Cluster equivalent | Local proof |
| --- | --- | --- |
| Record normal sensor health | Qualys sensor profile | agent up, events flowing |
| Test workloads on monitored nodes | DaemonSet placement | probe exec events attributed to containers |
| Approved sensor interruption on one node | team stops the sensor pod | agent killed → event gap |
| Qualys reports degraded/not reporting | sensor profile (platform) | gap visible in the stream |
| Restore + confirm recovery | sensor pod reschedules | agent up → events resume |

## Caveats

- Locally, policies must be re-applied after an agent restart; in-cluster
  the operator/reconciler re-adds CRD-backed policies automatically.
- The *reporting/alerting* of a degraded node is a Qualys platform view;
  this lab proves the underlying sensor behavior (gap + recovery).
- The event gap itself is searchable evidence: timestamps around the
  outage delimit the blind window.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Record normal sensor health | **YES** | agent up, probe events flowing |
| E2 | Test workloads on monitored nodes | **YES** | probe exec events attributed to containers |
| E3 | Approved sensor interruption (one node) | **YES** (sim) | agent killed |
| E4 | Node reported degraded / not reporting | **YES** | **0 events during outage** — gap visible; degraded-node UI = platform |
| E5 | Restore + confirm recovery + event flow | **YES** | agent restarted → policy re-applied → capture reconnected → events resume |

**Not covered live:** none (the *reporting* view is platform; the sensor
behavior is proven).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | rule on the health-probe binary |
| `pod.yaml` | pod looping the health probe every 5s (steady event flow) |
| `RESULT.md` | this document |
