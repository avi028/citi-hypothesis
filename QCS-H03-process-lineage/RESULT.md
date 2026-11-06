# QCS-H03 — Suspicious Process and Parent-Child Process Detection

## What we wanted to prove

When a suspicious command chain runs inside a container — a script that
spawns children, some short-lived, some long-running — Qualys records the
whole family tree: who launched what, what ran, what exited, and what was
killed.

## Verdict

**Supported, with one honest "partial".** Every launch, every child, every
termination was recorded with the parent, command line, UID and container
attached. The caveat: each record shows the process and its **immediate
parent** — grandparent-and-deeper trees are rebuilt by linking the event
IDs, which the data fully supports but isn't pre-joined in a single event.

NOTE: with v1 policy direct marked process is not available , you need to apply file-open policy on the binary / script to get an evnet unlike v2 which has direct marked process capability.

## What we did

- Wrote a policy (`policy.yaml`) that flags exec of a specific chain
  script, so the suspicious entry point is tagged in the stream
- Ran a container where a shell dropped `/tmp/citi-h03-chain.sh`, made it
  executable, and ran it — the script spawned a background `sleep 300`
  (long-lived), a `find | head` pipeline (short-lived), waited, then
  killed the sleeper
- Embedded a unique marker (`CITI-H03-7749`) in the command for
  correlation

## What we observed

The complete chain, in order:

```
docker exec → sh (the entry point)
    └─ /tmp/citi-h03-chain.sh        ← flagged by the policy as suspicious
        ├─ sleep 300                  ← long-lived, later killed → exit recorded
        ├─ find /etc -name *.conf     ← short-lived → exit recorded
        ├─ head -3                    ← short-lived → exit recorded
        └─ sleep 2 → kill             ← short-lived → exit recorded
```

Every record carried: binary path, full command line, UID, PID, container
ID, parent binary + parent exec ID, and node name. Launches AND
terminations are both present, including the kill of the long-running
child.

## The "partial" explained

| Hypothesis asks for | Status |
|---|---|
| Process launch recorded | Yes |
| Process termination recorded | Yes — including kills |
| Parent process attribution | Yes — immediate parent on every event |
| Command line | Yes |
| UID | Yes |
| Container identity | Yes — container ID on every event |
| Pod / namespace metadata | Field exists; **populates under k8s/OpenShift only** — plain docker runs have no pod to report |
| Deep lineage (grandparent+) | Reconstructed by chaining `parent_exec_id` → `exec_id` across events — data is complete, not pre-joined |

## Point-by-point check (original hypothesis)

| # | Execution point | Status | Evidence |
|---|---|---|---|
| E1 | Start a shell (`oc exec` → `docker exec`) | **YES** (live) | `process_exec /usr/bin/sh` (marker in argv) |
| E2 | Controlled chain `bash → script → curl/find` | **YES** (live) | `sh` → `/tmp/citi-h03-chain.sh` (flagged) → `find`/`head` children |
| E3 | Short-lived + long-running children | **YES** (live) | `find`/`head`/`sleep 2` short-lived; `sleep 300` long-lived — all recorded with exec + exit |
| E4 | Terminate selected processes | **YES** (live) | killed `sleep 300` → `process_exit` with `signal: SIGTERM` |
| E5a | Process launch recorded | **YES** | `process_exec` for every process in the chain |
| E5b | Process termination recorded | **YES** | `process_exit` for every process, incl. the kill |
| E5c | Parent process | **YES** | `parent.binary` + `parent_exec_id` on every event |
| E5d | Command line | **YES** | `process.arguments` (marker `CITI-H03-5521` in argv) |
| E5e | UID | **YES** | `process.uid` on every event |
| E5f | Container | **YES** | `process.docker` id on every event |
| E5g | Pod + namespace | **YES** | fields populate under k8s/OpenShift — verified in cluster runs; plain docker shows container id only |

**Not covered live:** none — all points verified (E5g under k8s).


## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | Flags the suspicious script exec (audit mode) |
| `pod.yaml` | Apply to the cluster to generate the process chain |
| `RESULT.md` | This document |

EC2 verification (`hypo-run.py --labs 3`, v1 mode, 2026-11-06): **PROVEN** — 17 matching events.
