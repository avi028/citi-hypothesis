# QCS-H11 — Privilege Escalation Configuration Detection

## What we wanted to prove

When a workload runs with elevated privileges (extra capabilities, root,
setuid binaries), does Qualys flag the elevated runtime context — and can
it tell an elevated exec from a normal one?

## Verdict

**Supported for runtime context; the pod-spec admission verdict is a
separate concern.** With `--enable-process-cred`, every exec event carries
the process's capability sets (`process.cap.permitted/effective`) and
`binary_properties` (setuid/setgid/file-caps). A raw TracingPolicy
capability-change hook fired **exactly once — on the container granted
CAP_SYS_ADMIN, and never on the normal control**.

## What we did

- Policy: a v2 process rule flags exec of the probe binary (`id`); a raw
  `tracingpolicy.yaml` adds `matchCapabilityChanges: Effective In
  [CAP_SYS_ADMIN]` on `security_bprm_check` (v2 has no capability rule type)
- Workload A: `docker run --cap-add=SYS_ADMIN debian id`
- Control B: `docker run debian id` (default caps, no SYS_ADMIN)

## What we observed

| | Elevated (A) | Normal (B) |
|---|---|---|
| `process.cap.permitted` contains CAP_SYS_ADMIN | **yes** | no |
| v2 exec-flag event (probe binary) | yes | yes (it watches the binary, not the privilege) |
| cap-change event (`matchCapabilityChanges`) | **1 event** | **0 events** |

- The exec events carry container id (`docker`), binary, argv; pod/namespace
  fields populate under k8s/OpenShift.
- The cap-change raw policy fired once for the privileged container and
  zero times for the control — a clean positive/negative pair.

## Caveats

- **v2 cannot filter on capabilities** — a cap-based rule needs the raw
  TracingPolicy (Future implementation: a v2 `matchCapabilities` field).
- **Admission vs runtime is two different systems.** Whether OpenShift
  *admits* the pod (SCC: anyuid, SYS_ADMIN, privileged) is recorded by
  OpenShift admission; the Qualys evidence is the *runtime context* of
  what actually ran. Correlate SCC admission audit with the exec events.
- `security_bprm_check` policy events attribute the exec'ing process
  host-side for a container's *first* process (runc context); the paired
  `process_exec` event carries the container id — join on exec_id.
- Risky *config* dimensions in the hypothesis (root UID, added caps,
  allowPrivilegeEscalation, hostPID, privileged) are all visible via the
  same mechanism: root uid → `process.uid`, caps → `process.cap`, and
  hostPID/privileged pods show namespace fields on events.

## Future implementation

A v2 `matchCapabilities`/`matchCapabilityChanges` rule field (today only
via raw TracingPolicy).

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | v2 process rule on the probe binary (audit) |
| `tracingpolicy.yaml` | raw cap-change hook on `security_bprm_check` |
| `policy-v1.yaml` | v1 has no capability base-policy; closest is file-open on the probe binary |
| `pod.yaml` | restricted control + SYS_ADMIN/root elevated pods (one risky setting at a time) |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H11-priv-escalation/policy.yaml
./tetra tracingpolicy add citi-hypothesis/QCS-H11-priv-escalation/tracingpolicy.yaml
docker run --rm --cap-add=SYS_ADMIN debian:stable-slim id   # elevated
docker run --rm debian:stable-slim id                        # control
```

Result: 1 cap-change event (elevated only); exec events show
`CAP_SYS_ADMIN` in permitted caps for A, absent for B.