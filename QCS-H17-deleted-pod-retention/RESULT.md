# QCS-H17 — Deleted Pod Historical Activity and Event Retention

## What we wanted to prove

After a pod and its container no longer exist, is the runtime evidence of
what it did still available and searchable?

## Verdict

**Supported.** A short-lived container ran a file + process + network
sequence, was force-deleted, and its **11 events remained in the event
stream**, searchable by the recorded container id (and by a unique marker
in the command line). Retention *duration* is a platform setting (e.g.
the 7-day window referenced in the hypothesis) — the sensor itself does
not delete evidence with the pod.

## What we did

- Policy: v2 file-open rule on a payload path + egress rule on :8080
- Workload: container wrote a payload file, read it, connected to the
  internal endpoint, then `docker rm -f` (simulates pod deletion / Job
  completion)

## What we observed

- Container id `5599f23125a0…` — recorded *before* deletion.
- After deletion: **11 events** for that container remain: exec/exit of
  bash/date/cat/sleep (base stream) + 5 policy events (`payload-open` by
  cat, `egress-audit` to :8080).
- The payload marker (`CITI-H17-RETENTION`) is also searchable — events
  were recovered by marker even after the container id lookup.

## What "retention" means where

| Ask | Where it works |
|---|---|
| Events survive pod deletion | Yes — this lab (sensor writes to the export/backend, not to the pod) |
| Search by pod UID / container id / image digest | Container id proven; pod UID/image digest fields populate under k8s |
| How long events are kept | Platform retention setting (e.g. 7 days) — not a sensor property |
| Full activity reconstruction | Yes — exec/exit + policy events join by exec_id chain + container id |

## Caveats

- Local capture here appends to `events.jsonl`; production retention
  depends on the Qualys platform backend configuration.
- Reconstructing "what happened" after the fact works because every event
  carries exec_id/parent_exec_id + container id — the same join used in
  H03/H18.

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | payload-open + egress rules that tag the evidence |
| `policy-v1.yaml` | v1 equivalents |
| `pod.yaml` | short-lived Job (file + process + network burst, auto-removed) |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H17-deleted-pod-retention/policy.yaml
CID=$(docker run --rm -d --name citi-h17-burst debian:stable-slim sleep 300)
docker exec citi-h17-burst bash -c 'echo "payload CITI-H17-RETENTION" > /tmp/citi-h17-payload.txt
  cat /tmp/citi-h17-payload.txt
  exec 3<>/dev/tcp/172.17.0.1/8080'
docker inspect citi-h17-burst --format '{{.Id}}'   # record the id
docker rm -f citi-h17-burst                        # delete the container
# search the event stream by the recorded id — events remain
```

Result: 11 events for the deleted container, 5 policy-matched.