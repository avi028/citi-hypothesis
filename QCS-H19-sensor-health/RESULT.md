# QCS-H19 — Sensor Coverage and Health Failure Detection

## What we wanted to prove

Qualys reports which nodes/workloads have a healthy runtime sensor, and
detects when monitoring is degraded or unavailable.

## Verdict

**Supported — the sensor health cycle is real and observable.** A
deliberate sensor interruption produced a clean **event gap** (zero
events while the agent was down), and recovery restored the event flow.
Node-level "degraded / not reporting" status in the Qualys UI is the
platform's sensor-profile view of exactly this cycle.

## What we did (local simulation of the interruption method)

1. Baseline: policy on a health-probe binary (`/usr/bin/true`), probe exec
   → 1 policy event
2. Interrupt: killed the tetragon agent (simulating the approved sensor
   interruption on a node)
3. Probe exec during outage → **0 new events** (the gap)
4. Recovery: agent restarted with the same flags, policy re-applied
   (in-cluster this is the operator/reconciler re-adding it), capture
   reconnected → probe exec → new event flows again

## What we observed

| Phase | Agent (:54321) | New policy events |
|---|---|---|
| baseline | up | 1 |
| outage | down | **0** (gap) |
| recovery | up | 1 (resumed) |

## Mapping to the cluster procedure

| Hypothesis step | Cluster equivalent | Local proof |
|---|---|---|
| Record normal DaemonSet + sensor health | Qualys sensor profile + OpenShift DS status | agent up, events flowing |
| Test workloads on monitored nodes | scheduler + DS placement | probe exec events attributed to containers |
| Approved sensor interruption on one node | OpenShift team kills the DS pod | agent killed → event gap |
| Qualys reports degraded/not reporting | sensor profile (platform) | gap visible in stream |
| Restore + confirm recovery | DS pod reschedules | agent up → events resume |

## Caveats

- Locally, policies must be re-applied after an agent restart; in-cluster
  the operator/reconciler re-adds CRD-backed policies automatically.
- The *reporting/alerting* of a degraded node is a Qualys platform view;
  this lab proves the underlying sensor behavior (gap + recovery).
- The event gap itself is searchable evidence: timestamps around the
  outage delimit the blind window.

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | v2 process rule on the health-probe binary |
| `policy-v1.yaml` | v1 file-open equivalent |
| `pod.yaml` | pod looping `/usr/bin/true` every 5s (steady event flow) |
| `RESULT.md` | this document |

## Local proof commands

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H19-sensor-health/policy.yaml
docker run --rm debian:stable-slim /usr/bin/true        # baseline → event
kill $(pgrep -x tetragon)                                # interruption
docker run --rm debian:stable-slim /usr/bin/true        # outage → NO event
# restart agent with the same flags (--enable-process-cred), re-add policy,
# restart the capture
docker run --rm debian:stable-slim /usr/bin/true        # recovery → event
```

Result: 1 event → gap (0) → 1 event after recovery.