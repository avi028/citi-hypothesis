# QCS-H14 — Malicious or Test File Hash Detection

## What we wanted to prove

Qualys can find a file by its known MD5/SHA-256 hash in an image and/or a
running container.

## Verdict

**Not covered by the runtime sensor.** Verified two ways: (1) by
inspection — no hash operator exists in any runtime policy filter, and
exec/file events carry **no file-hash fields**; (2) live — a marker file
with a known sha256 produced path-based events only. Hash search (image
scan + inventory) is a Qualys **platform** feature, not a runtime event.

## What we did

- Marker file with a known sha256 (a harmless stand-in for an antivirus
  test artifact)
- Policy: file-open/create on the marker **filename** (path-based — the
  best the runtime sensor can do)
- Workload (cluster): a copy baked into the image and one created at
  runtime, both opened

## What we observed

Both copies produced open events with the **path** and process
attribution — but no hash anywhere in the event args. No policy construct
can express "match this sha256": the events record *what was opened*,
never *what the bytes were*.

## The honest split

| Ask | Where it works |
| --- | --- |
| "Find images containing this hash" | Qualys image scan / inventory (platform) |
| "Is this hash running in a container?" | Not a runtime capability — the sensor cannot hash files or match hashes |
| "A file with this name/path was created/opened" | Runtime monitoring by path (this lab, H15) |

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Scan the image containing the test file | **NOT COVERED live** | platform scan |
| E2 | Search for its hash and filename | **NOT SUPPORTED (runtime)** | no hash operator/field in any policy or event — filename search only via path rules |
| E3 | Deploy + workload association | **YES** | opens recorded with container id |
| E4 | Create/copy the same file into the running container | **YES** | create + open events for the runtime copy |
| E5 | Image-scan vs runtime-file visibility | **Partial** | scan side can hash (platform); runtime side is path-only |

**Blunt:** hash-based detection is NOT a runtime-sensor capability; the
known sha256 appears nowhere in telemetry. A future runtime capability
would need file-content hashing in the agent — platform/roadmap item.

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | path-based open/create on the marker filename |
| `pod.yaml` | bakes the marker into the image + creates it at runtime |
| `RESULT.md` | this document |