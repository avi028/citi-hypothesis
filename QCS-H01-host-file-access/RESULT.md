# QCS-H01 — Container Escape / Host File Access Attempt

## What we wanted to prove

When a container reads a file that belongs to the underlying host
(a controlled directory mounted into it), Qualys sees it and can report
**who did it, from where, and what they touched**.

## Verdict

**It works.** Every read of the host marker file was recorded, and each
record told us exactly which container, which program, which command, and
which file.

## What we did

- Wrote a policy (`policy.yaml`) that says: *"report every read of a file
  whose path ends in `/QCS-H01/canary.txt`"*
- Created a marker file on the host at `/var/qualys-poc/QCS-H01/canary.txt`
- Ran a container that mounted that host folder read-only and did the
  things an attacker (or auditor) would do: `ls`, `stat`, `cat`,
  `sha256sum`

## What we observed

- `cat` and `sha256sum` — the two commands that actually read the file's
  contents — each produced a detection record containing:
  - the program used (`cat`, `sha256sum`)
  - the exact file path
  - which container it ran in (container id)
  - the full command that launched it, including its parent shell
  - the host (node) it happened on and the exact time
- `ls` and `stat` did not trigger a detection — correct behavior, since
  neither actually reads the file's contents. They still show up in normal
  process activity logs.
- Deleting the test setup does not remove history — the records are
  already captured in the event stream.

## One thing to know for the real deployment

The detection matches the file path **as the container sees it**. When we
mounted the same host folder at a different path (`/mnt/poc` instead of
`/var/qualys-poc/QCS-H01`), the reads were not flagged. So on OpenShift,
the `hostPath` in `pod.yaml` should be mounted at the same location the
policy expects — exactly as written in the manifest — or the policy's path
suffix should be relaxed to just the filename.

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | The detection rule (load with `tetra tracingpolicy add`) |
| `pod.yaml` | Apply to the cluster to generate the test activity |
| `RESULT.md` | This document |

## docker run command used for the local proof

```bash
docker run --rm \
  -v /var/qualys-poc/QCS-H01:/var/qualys-poc/QCS-H01:ro \
  debian:stable-slim sh -c '
    TARGET=/var/qualys-poc/QCS-H01/canary.txt
    ls -l /var/qualys-poc/QCS-H01
    stat "$TARGET"; cat "$TARGET"; sha256sum "$TARGET"'
```

Result: 4 detection events for `cat` and `sha256sum`, all with full
container, process, file, and node attribution.
