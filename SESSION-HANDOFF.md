# Session handoff — 2026-11-05

Everything below is committed and pushed to `avi028/citi-hypothesis` (`main`).

## Repo state (HEAD `f1674b5`)
- `hypo-run.py` v1.1.0 — lab runner (stdlib + PyYAML, k8s backend via kubectl; v1/v2 policy
  selection by CRS version; `--setup-sensor` installs the CRS chart per mode:
  v1 → `/home/ubuntu/arnav/145`, v2 → `/home/ubuntu/arnav/146`).
  **v1 process-visibility evidence fix (done this session)**: in
  `--policy-mode v1`, the evidence grep also matches **activity tokens** from
  `pod.yaml` + v1 `monitor-paths` (runtime script paths, lab markers, watched
  binaries) against the base sensor's policy-free `process_exec` stream;
  reports split evidence into policy-name/rule-id hits vs
  activity/process_exec hits (`lr.state.policy_evidence` /
  `activity_evidence`), and v1 verdict notes flag activity-only cases.
  `pod_activity_tokens()` extracts; `parse_policy_yaml()` now returns
  `monitor_paths`.
- `test-hypo-run.py` — 64 tests (15 new for tokens / event_matches kinds)
- `QCS-*` labs: unchanged this session; H20 still has no `policy-v1.yaml`
  (raw TracingPolicy only)

## Environment (EC2)
- Host: `ubuntu@ec2-184-198-30-234.compute-1.amazonaws.com`, key `C:/Users/arnmishra/Downloads/qatest 1.pem`
- Repo on box: `/home/ubuntu/tetragon/citi-hypothesis` (sudo for root; root kubeconfig works)
- Sensor chart dirs: v1 `/home/ubuntu/arnav/145`, v2 `/home/ubuntu/arnav/146`
- Cluster restored to the **146 (v2)** sensor after this session's v1 sweep
  (H20 v2 run with `--setup-sensor`)
- Qualys console pages (p04/p19) + `tools/e2e-verify` live in the separate repo `avi028/e2e-verify`

## Verified results
- v2 sweep: 20/20 PROVEN (sensor-log evidence) — 2026-11-04
- v1 sweep (all labs, `--policy-mode v1 --setup-sensor`): all 20 completed;
  v1 covers file/FIM + TCP egress (`net-tcp-open`); genuinely v1-impossible:
  process *rules* (audit/block on binaries — H11/H12/H16/H18/H19), memfd (H04),
  UDP/DNS `ip_output` (H06), network **ingress audit** (no v1 base-policy; v2 also
  marks ingress paths Not-applied), and H20 (no `policy-v1.yaml`).
- Base `process_exec` events are emitted by the sensor for every exec (policy-free),
  so process *visibility* exists in all labs — only policy-driven process *matching*
  is v2-only.
- **v1 process-visibility sweep (2026-11-05)** — H03/H11/H12/H16/H18/H19,
  `--policy-mode v1 --setup-sensor`, all PROVEN with split evidence
  (report: `/tmp/citi-labs/hypo-run-*.json`):
  - H03: policy 2 (lifecycle only), activity/exec 2 — chain script exec
    visible in base stream; exec-flag rule v2-only
  - H11: policy 3 (incl. File event), activity 3 — `id` exec + file-open
    detected; capability context v2/raw-TP only
  - H12: policy 2 (lifecycle only), activity 18 — "in use" proven via bash
    execs; binary rule v2-only
  - H16: policy 3 (incl. File event), activity 1 — **v1 kill-on-open
    enforced** (probe killed, pod Failed, enforcement_observed=true);
    exec-block rule v2-only
  - H18: policy 3, activity 14 — chain exec/cat/getent/exits visible at
    base level; rule-matching v2
  - H19: policy 3 (incl. File event), activity 4 — genuinely v1 (1.45+)

## Open thread (next session priority)
None — the v1 process-visibility evidence fix is complete and documented in
the README ("v1 process-visibility evidence" section). Natural next steps:
confirm the H20 v2 restore run (this session's sensor-restore doubles as a
H20 re-verify), or extend `pod_activity_tokens` for any future labs'
markers.

## How to run
```bash
cd /home/ubuntu/tetragon/citi-hypothesis
sudo PYTHONDONTWRITEBYTECODE=1 python3 test-hypo-run.py          # tests (PyYAML required)
sudo PYTHONDONTWRITEBYTECODE=1 python3 hypo-run.py --dry-run --labs all
sudo PYTHONDONTWRITEBYTECODE=1 python3 hypo-run.py --labs all --yes --setup-sensor
sudo PYTHONDONTWRITEBYTECODE=1 python3 hypo-run.py --labs 1,3-5 --yes --policy-mode v1 --setup-sensor
# reports: /tmp/citi-labs/hypo-run-<ts>.{json,md}
```