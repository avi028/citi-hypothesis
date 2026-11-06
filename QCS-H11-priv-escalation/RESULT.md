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

| | Elevated (root + CAP_SYS_ADMIN) | Normal (restricted control) |
| --- | --- | --- |
| Capability sets on the exec event contain CAP_SYS_ADMIN | yes | no |
| Exec of the probe binary flagged | yes | yes (the rule watches the binary, not the privilege) |

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