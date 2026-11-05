# Session handoff — 2026-11-05

Everything below is committed and pushed to `avi028/citi-hypothesis` (`main`).

## Repo state (HEAD `17e5317`)
- `hypo-run.py` — lab runner (stdlib + PyYAML, k8s backend via kubectl; v1/v2 policy
  selection by CRS version; `--setup-sensor` installs the CRS chart per mode:
  v1 → `/home/ubuntu/arnav/145`, v2 → `/home/ubuntu/arnav/146`)
- `test-hypo-run.py` — 47 tests (pass on EC2 with PyYAML; Windows needs `pip install pyyaml`)
- `QCS-*` labs: `policy.yaml` renamed to `policy-v2.yaml`; pod.yaml `runAsNonRoot`
  removed from test workloads (restricted/negative pods keep it); H18 pod.yaml heredoc
  indented (was invalid YAML)

## Environment (EC2)
- Host: `ubuntu@ec2-184-198-30-234.compute-1.amazonaws.com`, key `C:/Users/arnmishra/Downloads/qatest 1.pem`
- Repo on box: `/home/ubuntu/tetragon/citi-hypothesis` (sudo for root; root kubeconfig works)
- Sensor chart dirs: v1 `/home/ubuntu/arnav/145`, v2 `/home/ubuntu/arnav/146`
- Cluster currently running the **146 (v2)** sensor (H20's fallback group reinstalled it)
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

## Open thread (next session priority)
**v1 process-visibility evidence fix** (user-requested): in v1 mode, the evidence
grep currently matches only the v1 policy name, so process-lab verdicts are weak
(operator lifecycle lines, not detection payloads). Proposed: also grep the
**activity binaries from `pod.yaml`** (e.g. `/tmp/citi-h16-probe.sh`) so v1 verdicts
reflect real base-sensor `process_exec` events. Then re-run H03/H11/H12/H16/H18/H19
in v1 and produce the honest "covered vs not covered" table for the README.

## How to run
```bash
cd /home/ubuntu/tetragon/citi-hypothesis
sudo PYTHONDONTWRITEBYTECODE=1 python3 test-hypo-run.py          # tests (PyYAML required)
sudo PYTHONDONTWRITEBYTECODE=1 python3 hypo-run.py --dry-run --labs all
sudo PYTHONDONTWRITEBYTECODE=1 python3 hypo-run.py --labs all --yes --setup-sensor
sudo PYTHONDONTWRITEBYTECODE=1 python3 hypo-run.py --labs 1,3-5 --yes --policy-mode v1 --setup-sensor
# reports: /tmp/citi-labs/hypo-run-<ts>.{json,md}
```