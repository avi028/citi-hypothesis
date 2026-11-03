# QCS-H12 — Vulnerable Image Discovery and "In Use" Prioritization

## What we wanted to prove

Qualys finds a vulnerability in a deployed image — and can tell whether
the vulnerable package is *actually used* at runtime (invoked) or merely
*present* in the image.

## Verdict

**Partial — and the split is clean.** The registry side (vuln discovery,
CVSS, fix versions, "in use" UI) is a Qualys *image-scanning* capability,
not a runtime event — out of scope for the runtime sensor. The **runtime
"in use" half is proven**: a policy on the vulnerable binary fired for the
workload that invoked it and produced **zero events** for the workload
that never ran it.

## What we did

- Test "package": bash 5.2.37, present in `debian:stable-slim` (any
  package works — the mechanism is package-agnostic)
- Policy: v2 process rule `matchBinaries: In [/usr/bin/bash]` (audit)
- Workload A: invokes `bash -c 'echo in-use-marker'`
- Workload B: runs only `sh`/`dash` — bash present in the image, never invoked

## What we observed

- **A**: 1 policy event (`security_bprm_check`, arg `linux_binprm_arg.path=/usr/bin/bash`) + the paired `process_exec` with container id `34805c32…`, argv `-c "echo in-use-marker"`.
- **B**: **0 policy events** — the package sits in the image but produces no runtime signal.
- Join for the full picture: policy event (which binary matched) + exec event (which container) + image-scan result (which CVE).

## The "in use" logic (how this maps to the hypothesis)

| Input | Where it comes from |
|---|---|
| Image X contains package P vV, CVE with CVSS | Qualys registry scan (platform) |
| P is *invoked* by workload A | runtime exec events (this lab) |
| P present but never invoked in B | absence of exec events (this lab) |
| "In use" verdict + remediation metadata | platform joins scan + runtime signals |

## Caveats

- Policy events for a container's first process attribute host-side; the
  paired `process_exec` carries the container id.
- "In use" here means "binary executed". Libraries loaded by other
  processes (e.g. OpenSSL as a shared lib) are not visible as execs — that
  gap is inherent to exec-based instrumentation.
- v1 has no process-exec base-policy; closest is file-open on the binary.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
|---|---|---|---|
| E1 | Scan image in registry | **NOT COVERED live** | Qualys registry scan — platform |
| E2 | Deploy image into test namespace | docker | debian:stable-slim (bash 5.2.37 as the "vulnerable package") |
| E3 | Invoke package in A, not B | **YES** | A runs `bash -c 'echo in-use-marker'`; B never runs bash |
| E4 | Compare vuln / exploitability / in-use | **YES** (runtime half) | A: 1 policy event; B: **0** — the in-use signal is binary-exec presence |
| E5 | Image/container/package/version/workload/remediation metadata | **Partial** | runtime side: container id + binary path + argv on events; scan metadata = platform |

**Not covered live:** E1/E4-scan/E5-scan legs (platform).

## eBPF-Agent events observed (2026-11-03 run)

```json
{"process_kprobe": {"policy_name": "citi-h12-vuln-pkg-exec-v2-vuln-pkg-exec", "function_name": "security_bprm_check",
 "process": {"binary": "/usr/lib/systemd/systemd"},
 "args": [{"linux_binprm_arg": {"path": "/usr/bin/bash"}}]}}
// exactly 1 event (workload A); workload B produced zero
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | v2 process rule on the target package binary |
| `policy-v1.yaml` | v1 file-open approximation |
| `pod.yaml` | used / unused workloads from images containing the package |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H12-vuln-image-in-use/policy.yaml
docker run --rm debian:stable-slim bash -c 'echo in-use-marker'   # A: invokes bash
docker run --rm debian:stable-slim sh -c 'echo never-runs-bash'    # B: does not
```

Result: exactly 1 policy event (A); zero for B.