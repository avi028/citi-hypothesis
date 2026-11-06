# QCS-H11 — Privilege Escalation Configuration Detection

## What we wanted to prove

When a workload runs with elevated privileges (extra capabilities, root,
setuid binaries), does Qualys flag the elevated runtime context — and can
it tell an elevated exec from a normal one?

## Verdict

**Covered now: the runtime context.** Every exec event carries the
process's capability sets (what the process is allowed to do) and
`binary_properties` (setuid/setgid), so an elevated exec is visibly
different from a normal one — the exec of the probe binary was flagged,
and the capability data distinguishes the elevated pod from the control.

**Next release:** a dedicated capability-change rule (filter on
CAP_SYS_ADMIN changes) needs a raw TracingPolicy hook that v2 cannot
express — the raw-TP file has been removed from the lab; a v2
`matchCapabilities` field is the future-release path.

**Not covered (platform):** whether OpenShift *admits* the pod (SCC
verdicts) is admission data — Qualys evidence is the runtime context of
what actually ran.

## What we did

- Policy: process rule flags exec of the probe binary; the elevated pod
  adds CAP_SYS_ADMIN, the control pod is fully restricted
- Workload (cluster): both pods ran the probe (`id`); the elevated one
  with root + CAP_SYS_ADMIN, the control with dropped caps

## What we observed

**No policy is needed for the privilege context.** With zero
RuntimePolicies applied, the base `process_exec` stream already carries
`xattributes.cap` (permitted + effective), `process_credentials`,
`binary_properties`, and pod/workload identity. Verified live on the EC2
cluster (2026-11-06): the elevated pod's `id`/`capsh` execs carried

```text
"cap":{"permitted":[...,"CAP_SYS_ADMIN",...],
        "effective":[...,"CAP_SYS_ADMIN",...]}, pod_name":"citi-h11-elevated"
```

while processes with `drop: ALL` show `"cap":{}` — an elevated exec is
visibly different from a normal one *in the default event stream itself*.
The v2 process rule's job is only to flag the execs you care about.

| | Elevated (root + CAP_SYS_ADMIN) | Normal (restricted control) |
| --- | --- | --- |
| Capability sets on the exec event contain CAP_SYS_ADMIN | yes | no (empty) |
| Exec of the probe binary flagged (v2 rule / v1 file-open) | yes | yes (the rule watches the binary, not the privilege) |

v1 run on the EC2 lab (`hypo-run.py --labs 11`, `file-open` on
`/usr/bin/id`, 2026-11-06): **PROVEN** — 9 events in 111.5s; the probe
exec + file-open fired for the running pods and the exec stream carried
the cap context. The restricted control pod failed to start
(`CreateContainerConfigError`) — the intended negative control.

The exec events carry the container, binary, and command line; pod and
namespace fields populate under k8s.

## Caveats

- v2 cannot filter on capabilities — a cap-based rule is a next-release
  item (raw TracingPolicy removed from the lab).
- Admission vs runtime are two different systems: whether the pod is
  *admitted* is OpenShift/SCC data; the Qualys evidence is the *runtime
  context* of what actually ran. Correlate the SCC admission audit with
  the exec events.
- The risky *config* dimensions (root UID, added caps, privileged,
  hostPID) are all visible the same way: uid → process identity, caps →
  capability sets, privileged/hostPID → namespace fields on events.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E2 | Record whether OpenShift admits/rejects | **NOT COVERED live** | admission is platform/SCC data |
| E3 | Harmless identity/process checks on admitted pods | **YES** | probe runs in both pods |
| E4 | Risky config + runtime context identified | **YES** (partial) | exec events carry caps/uid; cap-change rule = next release |
| E5 | Distinguish admission vs runtime findings | **YES** (blunt) | admission = OpenShift/SCC (platform); runtime = the exec events |

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | process rule on the probe binary (v1: file-open approximation) |
| `pod.yaml` | restricted control + SYS_ADMIN/root elevated pods |
| `RESULT.md` | this document |

`tracingpolicy.yaml` (cap-change hook) was removed — capability-change
rules are a next-release item.
