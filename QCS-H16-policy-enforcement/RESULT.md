# QCS-H16 — Runtime Policy Enforcement / Process Blocking

## What we wanted to prove

Qualys can move from audit-only monitoring to actually stopping a process
that violates a runtime policy — and the pod keeps running throughout.

## Verdict

**Supported.** The same process rule in audit mode logged the probe
execution and let it run (`rc=0`); switched to `action: block` the probe
was SIGKILLed at exec (`rc=137`, `KPROBE_ACTION_SIGKILL` on
`security_bprm_check`) while the pod continued to run normally.

## What we did

- Probe: harmless script `/tmp/citi-h16-probe.sh`
- Audit policy: v2 process rule, `action: audit` → run probe
- Enforce policy: same rule, `action: block` → run probe again

## What we observed

| Phase | Probe result | Pod stability |
|---|---|---|
| audit | `CITI-H16-PROBE-RAN`, rc=0 | still alive |
| enforce | killed at exec, rc=137 | still alive |

Enforce event: `process_kprobe | citi-h16-probe-enforce-v2-probe-exec-block |
security_bprm_check | action=KPROBE_ACTION_SIGKILL`.

## Beyond process kill — the rest of the response menu

The hypothesis asks about network deactivation, memory dumps, pod
termination, and image blocklisting:

- **Process/exec blocking** — proven here (v2 process rule, SIGKILL).
- **Filesystem write blocking** — proven in QCS-H02 (file rule `block`).
- **Pod network deactivation, memory dump, pod kill, re-deploy
  blocklist** — **not runtime-sensor capabilities.** These are Qualys
  platform response actions (and partially OpenShift admission). Record
  as platform/roadmap items; the runtime sensor's contribution is
  enforcement at the process/file hook level.

## Caveats

- `action: block` = SIGKILL at the hook (exit 137), not a clean
  "permission denied".
- Enforcement is per-policy-scope: keep block policies narrow
  (namespace/workload scoping) to avoid killing legitimate traffic.
- v1 has no process-exec base-policy — the exec-block leg is v2-only
  (v1 `action: kill` covers file operations only).

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | audit + enforce variants of the same process rule |
| `policy-v1.yaml` | v1 file-open kill approximation (no exec hook in v1) |
| `pod.yaml` | disposable pod dropping + running the probe |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H16-policy-enforcement/policy.yaml  # audit doc first
docker run --rm debian:stable-slim bash -c 'printf "#!/bin/sh\necho CITI-H16-PROBE-RAN\nexit 0\n" > /tmp/citi-h16-probe.sh
  chmod +x /tmp/citi-h16-probe.sh; /tmp/citi-h16-probe.sh; echo "rc=$?"'
# then apply the enforce doc and re-run the same container flow
```

Result: audit rc=0 → enforce rc=137 (`KPROBE_ACTION_SIGKILL`), pod stable.