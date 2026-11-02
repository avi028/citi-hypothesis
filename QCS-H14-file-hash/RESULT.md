# QCS-H14 — Malicious or Test File Hash Detection

## What we wanted to prove

Qualys can find a file by its known MD5/SHA-256 hash in an image and/or a
running container.

## Verdict

**Not supported by the runtime sensor.** Verified two ways: (1) by
inspection — no hash operator exists in RuntimePolicy v2 filters
(`matchFilePaths`/`matchBinaries`/`matchArguments` are path/binary/arg
string compares) nor in raw Cilium TracingPolicy arg operators; exec/file
events carry **no file-hash fields**; (2) live — the marker file with a
known sha256 produced path-based events only. Hash search (image scan +
inventory) is a Qualys *platform* feature, not a runtime event.

## What we did

- Marker file: `EICAR-SIMULATION citi-h14-marker` (harmless stand-in for
  an antivirus test artifact), sha256 `7ed7cf5c…32e3`
- Image-baked copy at `/etc/citi-h14-marker.txt` (scan-time artifact) and
  a runtime copy at `/tmp/citi-h14-marker.txt`
- Policy: v2 `open` + `create` on the marker filename (path-based — the
  best the runtime sensor can do)

## What we observed

- Both copies produced `security_file_open` events with the **path**
  (`/etc/citi-h14-marker.txt`, `/tmp/citi-h14-marker.txt`) and process
  attribution — but no hash anywhere in the event args.
- No policy construct can express "match this sha256". The events record
  *what was opened*, never *what the bytes were*.

## The honest split

| Ask | Where it works |
|---|---|
| "Find images containing this hash" | Qualys image scan / inventory (platform) |
| "Is this hash running in a container?" | Not a runtime capability — the sensor cannot hash files or match hashes |
| "A file with this name/path was created/opened" | Runtime FIM by path (this lab, H15) |

## Caveats

- Filename- or path-based policies will catch *named* artifacts; content
  hashing is not available at the runtime layer.
- A future runtime capability would need file-content hashing in the
  agent — record as platform/roadmap item, not current behavior.

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | v2 path-based open/create on the marker filename (what IS possible) |
| `policy-v1.yaml` | v1 file-open equivalent |
| `pod.yaml` | bakes the marker into the image + copies it at runtime |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H14-file-hash/policy.yaml
docker run --rm debian:stable-slim bash -c '
  printf "EICAR-SIMULATION citi-h14-marker\n" > /etc/citi-h14-marker.txt
  sha256sum /etc/citi-h14-marker.txt
  cp /etc/citi-h14-marker.txt /tmp/citi-h14-marker.txt
  sha256sum /tmp/citi-h14-marker.txt
  cat /tmp/citi-h14-marker.txt'
```

Result: path-only `security_file_open` events; zero hash fields in any
event payload.