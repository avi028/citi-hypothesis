# QCS-H12 — Vulnerable Image Discovery and "In Use" Prioritization

## What we wanted to prove

Qualys finds a vulnerability in a deployed image — and can tell whether
the vulnerable package is *actually used* at runtime (invoked) or merely
*present* in the image.

## Verdict

**Partial — and the split is clean.** The **runtime "in use" half is
covered**: a policy on the vulnerable binary fired for the workload that
invoked it and produced **zero events** for the workload that never ran
it. The registry side (vuln discovery, CVSS, fix versions, "in use" UI)
is a Qualys **image-scanning** capability — platform data, not a runtime
event.

## What we did

- Policy: process rule on the vulnerable binary (`/usr/bin/bash`, audit)
- Workload (cluster): workload A invokes the package; workload B runs the
  same image but never invokes it

## What we observed

- **A** (`citi-h12-used`): the `bash` exec is recorded — `Process-exec`
  event with binary `/usr/bin/bash`, parent `/usr/bin/sh`, pod and
  container attribution; the v1 `file-open` policy on the binary fires
  when it is loaded for execution.
- **B** (`citi-h12-unused`): **0 events** — same image, package present
  but never invoked → no runtime signal.

EC2 run (`hypo-run.py --labs 12`, v1 mode, 2026-11-06): **PROVEN** —
7 matching events in 51.8s, all on the used pod's chain.

The full picture is a join: policy event (which binary matched) + exec
event (which container) + image-scan result (which CVE — platform).

## Caveats

- "In use" here means "binary executed". Libraries loaded by other
  processes (e.g. OpenSSL as a shared library) are not visible as execs —
  that gap is inherent to exec-based instrumentation.
- v1 has no process-exec base-policy; its closest form is file-open on
  the binary.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Scan image in registry | **NOT COVERED live** | Qualys registry scan — platform |
| E3 | Invoke package in A, not B | **YES** | A runs the binary; B never does |
| E4 | Compare vuln / exploitability / in-use | **YES** (runtime half) | A: 1 policy event; B: **0** — in-use = binary-exec presence |
| E5 | Image/container/package/version/workload/remediation metadata | **Partial** | runtime side: container id + binary path + argv; scan metadata = platform |

**Not covered live:** the scan legs (platform).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | process rule on the target binary (v1: file-open approximation) |
| `pod.yaml` | used / unused workloads from images containing the package |
| `RESULT.md` | this document |
