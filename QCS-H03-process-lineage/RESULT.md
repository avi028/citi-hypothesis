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

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | Flags the suspicious script exec (audit mode) |
| `pod.yaml` | Apply to the cluster to generate the process chain |
| `RESULT.md` | This document |

## docker run command used for the local proof

```bash
docker run -d --name citi-h03 debian:stable-slim sleep 600
docker exec citi-h03 sh -c '
  MARKER="CITI-H03-7749"
  printf "#!/bin/sh\necho chain-marker %s\nsleep 300 &\nLP=\$!\n
find /etc -name \"*.conf\" | head -3\nsleep 2\nkill \$LP\n" "$MARKER" \
    > /tmp/citi-h03-chain.sh
  chmod +x /tmp/citi-h03-chain.sh
  /tmp/citi-h03-chain.sh'
```

Result: all 10 exec/exit records for the chain with parent attribution,
plus 1 policy-flagged event on the script exec.
