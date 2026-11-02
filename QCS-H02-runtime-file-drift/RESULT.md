# QCS-H02 — Runtime File Drift and Unauthorized Executable Creation

## What we wanted to prove

If someone drops a brand-new file or script into a running container —
creates it, changes it, makes it executable, runs it, renames it, deletes
it — Qualys records every step. And in enforcement mode, it can stop the
activity instead of just watching it.

## Verdict

**It works, in both modes.** Every stage of the file's life produced a
detection record. In enforcement mode, the unauthorized write and the
attempt to run the dropped script were both **killed on the spot** — the
script never ran.

## What we did

- Wrote a policy (`policy.yaml`) that says: *"report every create, write,
  permission change, rename, and delete under `/tmp/citi-h02/`"*
- Ran a container that — after startup — created a script in `/tmp`,
  modified it, `chmod +x`'d it, executed it, renamed it, and deleted it
- Then applied a second policy (`policy-enforce.yaml`) that says *"kill
  the process"* instead of *"report"*, and repeated the attack

## What we observed — audit mode

Every action produced a detection record naming the program, the full
command line, the container, the file path, and the node:

| Attacker action | Detection record |
|---|---|
| Create the script | "new file created" event |
| Append to the script | "file written" event (one per write) |
| `chmod 755` | "permissions changed" event |
| Execute the script | process-execution event (free with the base sensor) |
| `mv` rename | "file renamed" event — **both** old and new names captured |
| `rm` delete | "file deleted" event — name preserved even though file is gone |

Nothing was missed; even the delete leaves a searchable record.

## What we observed — enforcement mode

| Attempt | Result |
|---|---|
| `echo x > /tmp/citi-h02-block/evil.sh` | Shell **SIGKILLed mid-write** (exit 137). The kill itself is also recorded as an event. |
| Execute dropped script `/tmp/citi-h02-block/drift.sh` | **Killed before it ran** (exit 137); the script's payload never executed. |

## One thing to know

- "Block" means the offending **process is terminated** (SIGKILL) at the
  moment it touches the watched path or tries to exec — it is not a clean
  "permission denied", the actor dies. That's the intended behavior for
  enforcement.
- The audit policy and the enforce policy are separate RuntimePolicy
  files; on OpenShift you'd apply audit first, then switch to enforce.

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | Audit-mode detection rules (create/write/metadata/rename/delete) |
| `policy-enforce.yaml` | Enforcement rules — block writes + block execution |
| `pod.yaml` | Apply to the cluster to generate the drift activity |
| `RESULT.md` | This document |

## docker run command used for the local proof

```bash
# audit phase
docker run --rm debian:stable-slim sh -c '
  DIR=/tmp/citi-h02; mkdir -p "$DIR"
  printf "#!/bin/sh\necho drift-v1\n" >  "$DIR/drift.sh"
  printf "#!/bin/sh\necho drift-v2\n" >> "$DIR/drift.sh"
  chmod 755 "$DIR/drift.sh"; "$DIR/drift.sh"
  mv "$DIR/drift.sh" "$DIR/drift.sh.renamed"; rm "$DIR/drift.sh.renamed"'

# enforce phase (script staged from host so it exists inside the blocked dir)
docker run -d --name citi-h02-enf \
  -v /tmp/citi-h02-stage/drift.sh:/tmp/citi-h02-block/drift.sh:ro \
  debian:stable-slim sleep 600
docker exec citi-h02-enf sh -c 'echo x > /tmp/citi-h02-block/evil.sh'  # rc=137, killed
docker exec citi-h02-enf /tmp/citi-h02-block/drift.sh                  # rc=137, killed
```
