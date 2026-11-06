# SESSION-HANDOFF — citi-hypothesis working notes (2026-11-06)

Read this first in a new session. Repo = Qualys runtime-detection hypothesis
labs (QCS-H01..H20); each lab ships `pod.yaml`, `policy-v1.yaml`/`policy-v2.yaml`,
and `RESULT.md`. This session: fixing labs so their workloads self-drive and
verifying them on a live EC2 k8s lab.

## Environment access

### EC2 lab (primary — Qualys sensor installed)

```bash
ssh -i "C:\Users\arnmishra\Downloads\qatest 1.pem" \
    ubuntu@ec2-184-198-30-234.compute-1.amazonaws.com
```

- passwordless `sudo`; kubectl only works via `sudo kubectl`
- cluster: single-node k8s v1.28.15 (`arnav-k8s-arm`), CNI **enforces
  NetworkPolicy** (H07 deny leg really timed out, rc=28)
- sensor: `qualys-runtime-sensor-9zmqn` in ns `qualys` (agent 1.8.0-0,
  CRS 1.45.0)
- labs live at `/home/ubuntu/tetragon/citi-hypothesis/` — **NOT a git repo**;
  push file changes with `scp` to `/tmp` then `sudo cp` (dir is root-owned)
- `hypo-run.py` at `/tmp/hypo-run.py` (current version)

### RD-Lab (secondary — tetragon standalone + minikube)

`ssh RD-Lab` (= `root@10.115.67.211`, key `~/.ssh/id_rsa`, in ~/.ssh/config)

- repo `/root/work/tetragon` (git, branch `CMS-35420-process-audit`);
  lab dir `/root/work/tetragon/citi-hypothesis` uses older `policy.yaml`
  naming (no `-v2` suffix)
- minikube up; tetragon+tetra binaries built; no agent currently running;
  start with `citi-hypothesis/setup.sh` (warns: not on base branch
  `release/v1.6-1-q5`)

## How to run a lab on the EC2 lab

```bash
# 1. push changed files
scp -i "qatest 1.pem" <file> ubuntu@<host>:/tmp/x.yaml
ssh ... "sudo cp /tmp/x.yaml /home/ubuntu/tetragon/citi-hypothesis/<LAB>/<file>"

# 2. run (v1 default; add --policy-mode v2 where needed)
sudo python3 /tmp/hypo-run.py --labs 7 --yes \
    --labs-dir /home/ubuntu/tetragon/citi-hypothesis
# or manual:
sudo kubectl apply -f <lab>/policy-v1.yaml
sudo kubectl apply -f <lab>/pod.yaml

# 3. evidence — IN-POD LOG FILE, rotates fast (grep promptly):
sudo kubectl exec -n qualys qualys-runtime-sensor-9zmqn -- sh -c \
  'grep "Network Activity payload" \
   /usr/local/qualys/runtime-sensor/data/logs/runtime_sensor.log'
```

## Key findings this session (don't relearn)

- **Network Activity / tcp_connect events land in `runtime_sensor.log`**
  (in-pod file), not necessarily `ebpfAgentLogFile.log` and not reliably in
  `kubectl logs`. Both sensor log files **rotate aggressively** — events can
  be gone in minutes; grep immediately or via hypo-run.
- **v1 rate-limit `1s` scope `pod` drops same-second connects.** H08's two
  back-to-back uploads lost the 2nd event; spacing legs `sleep 2` fixes it
  (verified: 2 curls >1s apart → 2 `Network Activity` events).
- **Applying policy + pod together can race policy arming.** hypo-run waits
  for the approval gate (`Applied` / sensor-log confirmation) — use it, or
  add the workload after the policy is live. Early connects can also miss
  pod attribution.
- **`pod.yaml` must be self-driving.** Several labs shipped pods that just
  `sleep` or target nonexistent services — applied alone they produce no
  events. Fixes so far: H07 (whole allow→deny sequence automated via SA +
  netpol-delete Role), H08 (receiver svc/pod added — was NXDOMAIN → curl
  never connected).
- `dst_endpoint.ip` shows the **ClusterIP** (connect-time tuple, pre-DNAT).
- httpd answers `PUT` with 405 — fine, `tcp_connect` records the attempt.
- Events carry `disposition:"Allowed"/status:"Success"` = the kprobe
  posted the event, NOT the network outcome (attempt ≠ outcome, the H06/H07
  lesson).
- `Process-exec payload` DEBUG lines batch-flush — same timestamp on many.
- hypo-run reports: `/tmp/citi-labs/hypo-run-<ts>.{json,md}` — JSON stores
  counts only, not evidence lines.

## Commits pushed (origin/main, github.com/avi028/citi-hypothesis)

| commit | change |
| --- | --- |
| `54e66d4` | H07 pod.yaml: automated allow→API-delete→deny→retry (SA+Role) |
| `6de31d3` | H07 RESULT.md: automated run, S2 now covered |
| `1e6a737` | H08 pod.yaml: added `citi-h08-recv` ns + receiver httpd + svc |
| `4e8cc5b` | H08 RESULT.md: receiver + PROVEN run (37 events) |
| `f8345ab` | H08 pod.yaml: `sleep 2` between uploads (v1 rate-limit) |
| `18894ca` | H08 RESULT.md: rate-limit caveat documented |

## Verified run results (EC2, v1 mode)

- H07: PROVEN — 34 events; toolbox log `baseline rc=0` → netpol delete
  `Status: Success` → `denied rc=28` (CNI enforces!)
- H08: PROVEN — 37 events; file-open + Network Activity on same chain;
  `curl` attributed through runtime `/tmp/citi-h08-upload.sh`

## Working through labs — where we are / what's next

- Done + verified live: H07–H19.
- **H09 verified (2026-11-06):** PROVEN, 22 events — token opens + both
  API connects recorded ~2s apart after adding `sleep 1/2` between the
  reads/curls (commit `c8747ed`). Its pod.yaml already self-drove; only
  the rate-limit spacing was needed.
- **H10 verified (2026-11-06):** PROVEN, 20 events — 4 API calls
  (2 allowed + 2 denied on :443) each produced a `Network Activity`
  connect ~2s apart after `sleep 2` spacing (commit `bf36884`).
- **H11 verified (2026-11-06):** PROVEN, 9 events (v1 file-open on
  /usr/bin/id). Cluster CRD serves **v1 only** (sensor CRS 1.45.0,
  chart `~/qcs-sensor` = 1.45.0-0) — v2 policy files can't apply here.
  **Key finding: base `process_exec` events carry
  `xattributes.cap`/`process_credentials`/`binary_properties` with NO
  policy applied** — elevated pod's execs showed CAP_SYS_ADMIN;
  `cap:{}` = genuinely empty caps (drop ALL), not missing instrumentation.
  Restricted control pod fails to start (expected negative control).
- **Next: H12+ in sequence** — same checklist: self-driving workload?
  target defined? connects >1s apart? v2-only labs (H01,H12,H16,H18,H20
  legs) can only approximate on this cluster — CRD is v1.
