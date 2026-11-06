# 🔬 CRS 2.0 — Runtime-Detection Hypothesis Book

**Twenty self-contained labs proving what the Qualys runtime sensor detects on Kubernetes.**

[![Labs](https://img.shields.io/badge/hypothesis%20labs-20-0969DA)](#labs)
[![Verified](https://img.shields.io/badge/live%20verified-20%2F20%20PROVEN-2DA44E)](#verified-results)
[![CRS v1](https://img.shields.io/badge/CRS%201.45-v1%20policies-8250DF)](#policy-modes-v1-default-v2-auto)
[![CRS v2](https://img.shields.io/badge/CRS%201.46%2B-v2%20policies-B54708)](#policy-modes-v1-default-v2-auto)
[![Backend](https://img.shields.io/badge/backend-Kubernetes%20API-1B7C83)](#running-the-labs)

---

Each lab ships a policy, a workload manifest, and a recorded result —
`QCS-H01` through `QCS-H20`, each proving (or disproving) one
runtime-detection hypothesis against a live Kubernetes cluster running
the Qualys runtime sensor.

**Status:** H02–H19 verified **PROVEN** on a live cluster in v1 mode
(CRS 1.45). H01 and H20 are v2-only (CRS 1.46). See
[Verified results](#verified-results).

## Running the labs

Everything runs through `hypo-run.py` — a self-contained runner (Python
stdlib only, no kubectl/helm/docker dependencies; it talks to the
cluster through the Kubernetes REST API: kubeconfig auth, CRD create and
status polling, pod logs, a minimal WebSocket exec client). Run it from
any host with admin access to the cluster.

### Prerequisites

- A Kubernetes cluster with the Qualys runtime sensor deployed —
  validated on single-node k8s v1.28.15, sensor agent 1.8.0-0:
  - **CRS 1.45** serves `qualys.com/v1` policies (v1 mode)
  - **CRS 1.46+** is required for v2 policies (process/exec rules —
    needed by H01, H20, and several v2-only legs)
- Credentials able to create `RuntimePolicy` CRs, pods and namespaces,
  and read sensor pod logs in the `qualys` namespace
- Python 3 for `hypo-run.py` (`sudo` on the cluster host; `--no-sudo`
  opts out)

### Run modes

**Dry run — plan only, zero side effects:**

```bash
sudo python3 hypo-run.py --dry-run               # preflight + plan for every lab
sudo python3 hypo-run.py --dry-run --labs 7      # plan just H07
```

**Normal run (default) — execute the lab, review in the Qualys UI:**

```bash
sudo python3 hypo-run.py --labs 2 --yes          # run H02
sudo python3 hypo-run.py --labs 2-8 --yes        # run H02 through H08
sudo python3 hypo-run.py --labs all --yes        # every lab supported by the mode
```

Each lab applies its policy, waits for the approval gate
(`RuntimePolicy.status.state = Applied`), applies the workload pod,
settles, cleans up, and reports `FINISHED`. Detection events are then
reviewed in the Qualys UI — normal mode does not read sensor logs or
print a verdict.

**Debug run — evidence grep + a verdict per lab:**

```bash
sudo python3 hypo-run.py --labs 8 --yes --debug
sudo python3 hypo-run.py --labs all --yes --debug --log-file run.log
```

`--debug` adds verbose logging plus the evidence stage: it greps the
sensor pod's log for policy-name / rule-id / workload-activity matches
(time-windowed to the lab, so a previous run's events are never
counted), prints a per-lab verdict (**PROVEN / NOT-PROVEN / SKIPPED /
ABORTED**), and the consolidated `hypo-run-<ts>.{json,md}` reports carry
the evidence counts. Use it when you want machine-checked evidence
rather than a UI review.

**Interactive:** `sudo python3 hypo-run.py` — pick labs, confirm each.

### Policy modes: v1 (default), v2, auto

`--policy-mode` selects which policy file each lab applies:

| Mode | Policy file | When |
| --- | --- | --- |
| `v1` (default) | `policy-v1.yaml` | CRS 1.45 — file + network detections |
| `v2` | `policy-v2.yaml` | CRS 1.46 — adds process/exec rules; required for H01 and H20 |
| `auto` | per lab | picks the form by each lab's minimum CRS version |

```bash
sudo python3 hypo-run.py --labs 1 --yes                     # H01 -> "not supported in v1"
sudo python3 hypo-run.py --labs 1 --yes --policy-mode v2    # H01 runs (v2-only lab)
sudo python3 hypo-run.py --labs all --yes --policy-mode v2  # v2 sweep
sudo python3 hypo-run.py --labs all --yes --policy-mode v2 --setup-sensor
```

- A lab whose policy form is missing reports `not supported in v1/v2`
  instead of silently switching (H01 and H20 have no v1 form).
- `--setup-sensor` reinstalls the sensor chart for the mode
  (v1 → CRS 1.45, v2 → CRS 1.46). Only use it when you want a sensor
  restart — if the sensor already runs the right version, leave it off.

### Running a lab manually (kubectl)

```bash
kubectl apply -f citi-hypothesis/QCS-H08-data-exfil/policy-v1.yaml
# wait for the approval gate — the same signal hypo-run polls:
kubectl get runtimepolicy <policy-name> -o jsonpath='{.status.state}'   # -> Applied
kubectl apply -f citi-hypothesis/QCS-H08-data-exfil/pod.yaml
# evidence (in-pod sensor log — rotates in minutes, grep promptly):
kubectl exec -n qualys <sensor-pod> -- sh -c \
  'grep "<policy-name>" /usr/local/qualys/runtime-sensor/data/logs/runtime_sensor.log'
# cleanup
kubectl delete -f citi-hypothesis/QCS-H08-data-exfil/pod.yaml
kubectl delete -f citi-hypothesis/QCS-H08-data-exfil/policy-v1.yaml
```

Apply the workload **after** the policy reports `Applied` — events fired
before the policy is armed are missed (and early connects can miss pod
attribution).

### Where the evidence lives

- **Normal mode:** review the detection events in the Qualys UI.
- **Debug mode / manual:** the sensor's in-pod log
  (`runtime_sensor.log`) carries `Network Activity payload`,
  `File event`, and `Process-exec payload` records. It **rotates
  aggressively** — events can be gone in minutes; `--debug` greps it
  automatically inside the lab window.
- Consolidated reports (JSON + Markdown, written atomically) land in
  `$RUN_DIR/hypo-run-<timestamp>.{json,md}`. The JSON stores counts, not
  evidence lines.

### Key flags (all also settable via `HYPO_RUN_*` env vars)

| Flag | Meaning |
| ------ | --------- |
| `--labs 1,3-5,7 / all` | selection by hypothesis number (QCS-H01 → 1 … QCS-H20 → 20); a lab that cannot run in the selected mode reports `not supported` |
| `--policy-mode v1/v2/auto` | policy form; **default v1** (v2 has the process/exec rules), `auto` picks by CRS version |
| `--debug` | verbose logging + sensor-log evidence grep + PROVEN/NOT-PROVEN verdicts; without it labs just run and report `FINISHED` |
| `--dry-run` | preflight + plan only, no side effects |
| `--yes / --no-prompt` | no interactive confirmation |
| `--no-color` | disable ANSI colors (auto-off when not a TTY; `NO_COLOR` env also honored); the log file is always plain |
| `--keep` | leave policy + pod in place after each lab |
| `--fail-fast` | stop the run after the first SKIPPED/NOT-PROVEN lab |
| `--setup-sensor` | install the CRS sensor chart matching the policy mode before running |
| `--backend auto/k8s/operator` | execution backend; auto = k8s API when a cluster answers (`operator` is a standalone dev fallback) |
| `--labs-dir DIR` | lab directory (default: repo root) |
| `--events-file FILE` | capture file (standalone backend only; the k8s backend reads sensor pod logs) |
| `--log-file FILE` | tee terminal output to a file |
| `--settle SECS` | wait after workload activity (default 5) |
| `--timeout-poll SECS` | policy-approval poll budget (default 60) |
| `--timeout-cmd SECS` | per-command timeout (default 30) |
| `--max-log-bytes` / `--max-events` | evidence window / print caps |

Per lab it: prints the hypothesis briefing + policy-to-workload mapping;
applies the policy file (`policy-v1.yaml` by default; `--policy-mode v2`
uses `policy-v2.yaml`, `auto` picks by CRS version) via the k8s API;
waits for the approval gate (`RuntimePolicy.status.state = Applied`);
applies `pod.yaml` and waits for the workload to run; settles; in
`--debug` mode greps the sensor logs for policy/rule-id evidence
(deduped, capped, time-windowed to the lab's start — in v1 mode it also
matches activity tokens from pod.yaml so process-lab verdicts reflect
the base sensor's policy-free `process_exec` stream, with policy vs
activity/exec hit counts split in the report); records the verdict
(**PROVEN / NOT-PROVEN / SKIPPED / ABORTED**, with weak-evidence notes
when a workload fails to start); and cleans up (delete policy + pod)
unless `--keep`.

Exit codes: `0` done, `1` preflight/env failure, `2` usage, `130`
interrupted (Ctrl+C; second Ctrl+C exits immediately). A pidfile lock
prevents concurrent runs. Run `python3 hypo-run.py --help` for the full
usage; `test-hypo-run.py` exercises the selection/parsing/event-matching
logic locally.

### Kubernetes notes for these labs

- **NetworkPolicy must be enforced by the CNI** for deny legs to
  actually be denied — verified live (H07's denied connect timed out,
  rc=28).
- **`pod`/`namespace` event fields only populate under k8s** — that is
  the attribution these labs verify.
- **`dst_endpoint.ip` shows the ClusterIP** (connect-time tuple,
  pre-DNAT).
- **v1 rate limit `1s` scope `pod` drops same-second connects** — lab
  workloads space repeated legs with `sleep 2` so each produces an
  event.
- **Workload pods are self-driving** — each `pod.yaml` generates its
  activity on its own once applied; no exec into the pod is needed.

## Lab anatomy

```text
citi-hypothesis/<LAB-NAME>/
├── policy-v1.yaml   # RuntimePolicy v1 (qualys.com/v1 — CRS 1.45)
├── policy-v2.yaml   # RuntimePolicy v2 (CRS 1.46 — process/exec rules)
├── pod.yaml         # k8s workload that generates the activity
├── RESULT.md        # hypothesis, what we ran, what we saw, verdict
└── tracingpolicy.yaml        # optional: raw Cilium fallback (see below)
```

### RuntimePolicy v1 (legacy) form

Every lab also ships `policy-v1.yaml`: the same detection in the legacy
`qualys.com/v1` schema (`spec.base-policy`, `monitor-*`/`match-binaries`,
and `action`). One document per base-policy — v1 has no rule list. On
the cluster it is applied with `kubectl` (or hypo-run); the conversion
webhook + operator translate it into hooks.

v1 differences vs v2 (verified by these labs):

- `monitor-paths` = **Prefix on the resolved path** only (no Postfix —
  `/var/run`→`/run` still applies, QCS-H09)
- `action`: `audit`→Post, `kill`→Sigkill
- **all Post actions get `rateLimit: 1m` (scope global) — `rate-limit:"0"`
  maps to the same default; it cannot be disabled.** Bursts lose events.
- file policies auto-add `matchNamespaces: Pid NotIn host_ns` — container
  opens only; host opens of the same path never fire.
- no v1 base-policy for process-exec (H03), memfd (H04 — next release),
  or DNS/UDP (H06 — next release) — those stay on v2 rules or are
  next-release items.

Copy `citi-hypothesis/TEMPLATE/` to start a new lab: write the hypothesis,
add the policy + pod manifests, run it on the cluster with hypo-run, then
record the outcome in `RESULT.md` — plain language, verdict up front.

## RuntimePolicy v2 capability

| Rule `type` | What it produces | Filters |
| --- | --- | --- |
| `file` | kprobes per `fileOperation`: `read`, `write`, `write-diff`, `create`, `delete`, `rename`, `open`, `metadata` (chmod/chown/truncate), `links` | `matchFilePaths`, `matchBinaries` |
| `process` | `security_bprm_check` kprobe (pre-exec — `block` stops the exec) | `matchBinaries` |
| `network` | egress audit → `tcp_connect` kprobe; egress block → `connect4`; ingress → `accept4` | `matchPorts`, `matchIPAddresses`, `matchProtocols`; `matchDNS`/`matchFQDN` only on egress block |

- `action`: `audit` → Post event; `block`/`kill` → SIGKILL the process.
- Operators: `In`, `NotIn`, `Prefix`, `NotPrefix`, `Postfix`, `NotPostfix`.
- Not translated (rule marked Not-applied): `matchQLPs`,
  `containerSelector`; `matchPorts`/`matchBinaries` on block/ingress
  network rules; `matchParentBinaries`/`matchArguments` on network rules.

## When a rule needs a hook RuntimePolicy v2 doesn't support

If a hypothesis needs a syscall/kprobe/tracepoint v2 cannot express —
e.g. `memfd_create`, `ptrace`, `mount`, UDP `ip_output`, uprobes — ship a
native **Cilium TracingPolicy** (`apiVersion: cilium.io/v1alpha1`) in the
lab as `tracingpolicy.yaml`; see `TEMPLATE/tracingpolicy.yaml`. Current
labs do not ship raw TracingPolicies — the legs that needed them (memfd,
cap-change, pod DNS, mount syscalls) are recorded in each lab's RESULT.md
as **next-release** items. Note: agent **1.8 already logs DNS natively**
(`MSG_OP_QUALYS_DNS` — fqdn + answers + src tuple), including pod
lookups to external resolvers; the kube-dns (cluster-internal) path is
the remaining gap.

### Future implementation note

Every hook exercised this way is a candidate for a future v2 rule type or
field. When a lab can only be expressed with a raw TracingPolicy, record
the missing field in `RESULT.md` under "Next release" — current gaps
found by these labs: a `memfd`/`fileless` rule type, `matchBinaries` on
memory-backed execs, kube-dns (cluster-internal) DNS visibility
(external-resolver pod DNS landed in agent 1.8), a capability-change
rule, and a `syscall` rule type for mount monitoring.

## Labs

| Lab | Hypothesis | Verdict | CRS |
| --- | --- | --- | --- |
| `QCS-H01-host-file-access` | Container reads a controlled host path → detected with attribution | Supported | 1.46+ |
| `QCS-H02-runtime-file-drift` | Post-deploy file create/write/chmod/rename/exec/delete → detected; enforce mode kills the actor | Supported | `1.45+*` |
| `QCS-H03-process-lineage` | Full parent/child lineage of a suspicious chain → recorded | Supported (immediate parent per event; pod fields need k8s) | 1.46+ |
| `QCS-H04-fileless-exec` | Inline/stdin fileless execution → visible via activity; file-based script is the control | Partial (script body invisible for stdin; memfd fileless = next release) | 1.45+ |
| `QCS-H05-east-west-visibility` | Cross-namespace connects → full 5-tuple + process + container per event | Supported (pod/ns names need k8s) | 1.45+ |
| `QCS-H06-north-south` | Outbound connects incl. refused/blackholed → recorded; unlisted ports → not; UDP DNS → next release | Supported (scoped to watched ports; UDP DNS = next release) | 1.45+ |
| `QCS-H07-netpol-denied` | Denied connection attempts → still recorded, identical to successes | Supported (attempt ≠ outcome; corroborate with platform logs) | 1.45+ |
| `QCS-H08-data-exfil` | File read + outbound send correlated on same PID/parent chain, even via runtime script | Supported (contents never captured; DNS leg = next release) | 1.45+ |
| `QCS-H09-service-account-token` | SA token file open + K8s API egress → both recorded with process + container attribution | Supported (API request/verdict inside TLS → audit log only) | 1.45+ |
| `QCS-H10-cross-ns-rbac` | Authorized vs unauthorized API calls → identical connect events with attribution | Supported (allow/deny only in K8s audit log) | 1.45+ |
| `QCS-H11-priv-escalation` | Elevated exec (CAP_SYS_ADMIN) → exec events carry cap sets; cap-change rule = next release | Supported (runtime context; admission verdict is SCC's) | 1.46+ |
| `QCS-H12-vuln-image-in-use` | Vuln package invoked in A → event; present-but-unused in B → none | Partial (runtime "in use" proven; scan leg is platform) | 1.46+ |
| `QCS-H13-image-lineage-drift` | Post-deploy create/write/open recorded with attribution | Partial (drift proven; digest/layer diff is platform) | 1.45+ |
| `QCS-H14-file-hash` | No hash fields/operators in events or policies | Not supported (path-only; hash search is platform) | 1.45+ |
| `QCS-H15-suspicious-filename` | Full FIM lifecycle on Login.jsp/Sql.java/package.json incl. child re-create | Supported | 1.45+ |
| `QCS-H16-policy-enforcement` | Audit rc=0 → block rc=137 (SIGKILL at exec), pod stable | Supported (net-deact/memdump/pod-kill/image-block = platform) | 1.46+ |
| `QCS-H17-deleted-pod-retention` | 11 events survive container deletion, searchable by id/marker | Supported (retention window = platform setting) | 1.45+ |
| `QCS-H18-signal-correlation` | exec → file → read → DNS → connect chain reconstructs from events | Supported at sensor level (joinable; DNS leg = next release) | 1.46+ |
| `QCS-H19-sensor-health` | Interruption → event gap; recovery → events resume | Supported (degraded-node UI = platform sensor profile) | 1.45+ |
| `QCS-H20-volume-mount-monitoring` | File activity inside mounted volumes → recorded; mount syscall monitoring = next release | Partial (mounted-volume reads covered; mount syscall = next release) | 1.46+ |

## Verified results

Full pass of all 20 labs on a live cluster (k8s backend): policy applied
via the k8s API → approval gate (`RuntimePolicy.status.state = Applied`)
→ workload pod → event evidence from the sensor logs → verdict →
cleanup. Every lab's test workload starts; negative/restricted control
pods still fail as intended.

| # | Lab | Verdict | Evidence | Duration |
| --- | ----- | --------- | ---------- | ---------- |
| 1 | QCS-H01-host-file-access | PROVEN | 4 | 133.7s |
| 2 | QCS-H02-runtime-file-drift | PROVEN | 20 | 20.5s |
| 3 | QCS-H03-process-lineage | PROVEN | 3 | 12.4s |
| 4 | QCS-H04-fileless-exec | PROVEN | 32 | 14.4s |
| 5 | QCS-H05-east-west-visibility | PROVEN | 11 | 12.7s |
| 6 | QCS-H06-north-south | PROVEN | 53 | 14.4s |
| 7 | QCS-H07-netpol-denied | PROVEN | 78 | 12.6s |
| 8 | QCS-H08-data-exfil | PROVEN | 107 | 14.5s |
| 9 | QCS-H09-service-account-token | PROVEN | 20 | 14.6s |
| 10 | QCS-H10-cross-ns-rbac | PROVEN | 36 | 16.7s |
| 11 | QCS-H11-priv-escalation | PROVEN | 3 | 131.7s |
| 12 | QCS-H12-vuln-image-in-use | PROVEN | 8 | 14.5s |
| 13 | QCS-H13-image-lineage-drift | PROVEN | 24 | 16.6s |
| 14 | QCS-H14-file-hash | PROVEN | 13 | 14.4s |
| 15 | QCS-H15-suspicious-filename | PROVEN | 30 | 22.5s |
| 16 | QCS-H16-policy-enforcement | PROVEN | 6 | 14.6s |
| 17 | QCS-H17-deleted-pod-retention | PROVEN | 377 | 133.0s |
| 18 | QCS-H18-signal-correlation | PROVEN | 417 | 16.4s |
| 19 | QCS-H19-sensor-health | PROVEN | 3 | 12.4s |
| 20 | QCS-H20-volume-mount-monitoring | PROVEN | 8 | 14.4s |

**20 / 20 PROVEN.** Evidence = matching detection events in the sensor
logs (policy-name / rule-id matches, deduped). H01/H11/H17 took longer
because their negative-control pods intentionally fail and the Job's
ready-wait runs its budget; the test workloads still ran and produced
evidence.

H02–H19 were subsequently re-verified in **v1 mode** (CRS 1.45) —
all PROVEN; per-lab runs and event counts are recorded in each lab's
`RESULT.md`.

### v1 coverage per lab (H01–H20)

**CRS version per lab**: `1.45+` = RuntimePolicy v1 suffices; `1.46+`
= RuntimePolicy v2 required (process/exec rules). Legs that need a raw
Cilium TracingPolicy hook are recorded as **next-release** items in the
lab's RESULT.md.

Every lab ships `policy-v1.yaml`; live-verified. Where a leg cannot be
expressed in v1 it is flagged in the lab's policy file and listed here:

- **Fully v1 (no v2 needed)**: H04 (inline/activity
  file + network legs), H05, H07 (net-tcp-open), H08 (file + network),
  H09, H10 (SA-token open + API ports), H19 (file-open health probe on
  `/usr/bin/true` — the steady probe exec stream is genuinely 1.45+).
- **Partial — one leg is v2-only**:
  - H02: drift create/write/metadata/rename/delete + `action: kill` are
    v1; the **exec-block** of the dropped script is a v2 process rule.
  - H03: v1 `file-open` approximates the launch marker; the **process-exec
    flag** is v2-only (no process base-policy in v1).
  - H04: **memfd fileless exec** — no v1 base-policy; **next release**
    (the raw `tracingpolicy*.yaml` form was removed from the lab).
  - H06: **UDP/DNS** leg — `net-tcp-open` is TCP only; agent 1.8 logs
    DNS natively (`MSG_OP_QUALYS_DNS`) for external-resolver lookups —
    kube-dns is **next release** (raw `ip_output` form removed from the lab).
  - H11: v1 `file-open` on `/usr/bin/id` fires at exec; the
    **capability context** (CAP_SYS_ADMIN) is v2-only, and a dedicated
    cap-change rule is **next release** (raw TP removed).
  - H12: v1 `file-open` on `/usr/bin/bash` fires when the vulnerable
    package is invoked; the **process rule** that flags the binary is
    v2-only.
  - H16: v1 `file-open` + `action: kill` on the probe script
    **enforces** (probe killed, pod Failed); the **exec-block** that
    keeps the pod stable is a v2 process rule.
  - H18: file + network legs are v1; the **chain-exec rule** is
    v2-only, and the **DNS leg** is **next release** (raw TP removed).
- **No v1 form**: H01 (host-file read needs the v2 `Postfix` operator to
  scope to the specific host file — v1 `monitor-paths` are Prefix-only, so
  v1 cannot determine the host file; no `policy-v1.yaml`) and H20
  (volume-mount monitoring — no `policy-v1.yaml`; mounted-volume file
  activity is v2, and the mount syscall leg is **next release**). v1 runs
  report `not supported in v1` for these instead of silently switching —
  use `--policy-mode v2` to run them.

#### v1 process-visibility evidence (how v1 process labs are judged)

v1 has **no process-exec base-policy**, so a v1 policy name alone never
matches a process *detection payload* — only operator lifecycle lines
("Adding policy …", "Successfully added policy …"). To judge process
labs honestly in v1 mode, `hypo-run.py` (v1.1.0) additionally greps
**activity tokens** — the workload's runtime script paths, lab markers,
and the v1 `monitor-paths` from `pod.yaml` — against the base sensor's
policy-free `process_exec` stream ("New process added to tree: …",
"Process-exec event payload"). Reports split evidence into
**policy-name/rule-id hits** vs **activity/process_exec hits**, and the
verdict notes flag the case where only activity/exec evidence matched.

v1 sweep re-run (2026-11-05, H03/H11/H12/H16/H18/H19,
`--policy-mode v1 --setup-sensor`, sensor-log evidence, all PROVEN):

| Lab | v1 policy form | policy hits | activity/exec hits | Honest v1 reading |
| --- | --- | --- | --- | --- |
| H03 | file-open `/tmp/citi-h03-chain.sh` | 2 (lifecycle only) | 2 | chain script exec visible in base stream; exec-flag rule v2-only |
| H11 | file-open `/usr/bin/id` | 3 (incl. File event) | 3 | `id` exec + file-open detected; capability context v2/raw-TP |
| H12 | file-open `/usr/bin/bash` | 2 (lifecycle only) | 18 | "in use" proven: bash execs visible; binary rule v2-only |
| H16 | file-open `/tmp/citi-h16-probe.sh`, `action: kill` | 3 (incl. File event) | 1 | v1 kill-on-open **enforced** (probe killed, pod Failed); exec-block rule v2-only |
| H18 | file-open payload + `net-tcp-open` 8080 | 3 | 14 | chain exec / cat / getent / exits visible at base level; rule-matching v2 |
| H19 | file-open `/usr/bin/true` | 3 (incl. File event) | 4 | health probe's steady exec stream visible — genuinely v1 |

All twenty labs carry verified `policy-v1.yaml` (legacy v1 schema)
except H20 (no v1 form — mounted-volume file activity is v2; the mount
syscall leg is next release); `ALL-HYPOTHESES.md`
consolidates both policy forms + observed data, plus the three "discuss
with Qualys" use cases (crypto-mining — mechanism verified in
`tools/miner-sim.yaml`; package search; unauthorized components).

## Execution-point coverage

Every lab's RESULT.md now carries a **"Point-by-point check"** table that
maps each setup (S*) and execution-flow (E*) point of the original
hypothesis to the recorded evidence (or marks it "Not covered"). Points
the runtime lab could not verify live are listed here — they are either
platform-only legs or require a cluster. This list is kept in sync with
the skill (`citi-hypothesis-labs`) so new labs follow the same rule.

| Lab | Execution points NOT covered (live) | Why / where it lives |
| --- | --- | --- |
| `QCS-H01-host-file-access` | E1 — restricted-v2 pod denial (live) | `citi-h01-restricted` cannot start on the cluster (`CreateContainerConfigError`) — denial at admission/pod-creation; path-level access denial not demonstrated (RESULT.md E1) |
| `QCS-H05-east-west-visibility` | S4 — NetworkPolicy (intended-path-only) enforcement | NetworkPolicy is a cluster/platform feature — needs OpenShift (RESULT.md S4) |
| `QCS-H05-east-west-visibility` | E5 — compare with OpenShift network/app logs | platform log comparison; minikube cluster available for the platform run (RESULT.md E5) |
| `QCS-H06-north-south` | S3 — OpenShift egress controls (only test dest permitted) | egress policy is a cluster/platform feature — needs OpenShift (RESULT.md S3) |
| `QCS-H07-netpol-denied` | S2/S5 — real NetworkPolicy + OpenShift network logs | simulated with iptables DROP; needs OpenShift (RESULT.md S2/S5) |
| `QCS-H08-data-exfil` | DNS leg of the correlation | kube-dns path not emitted; external-resolver pod DNS is logged natively in 1.8 — cluster-internal leg is **next release** (RESULT.md) |
| `QCS-H09-service-account-token` | S4/E5 — K8s/OpenShift API audit logs | platform leg (RESULT.md S4/E5) |
| `QCS-H10-cross-ns-rbac` | E3/E5 — API audit logs (403 + SA identity) | platform leg (RESULT.md E3/E5) |
| `QCS-H11-priv-escalation` | E2 — OpenShift admission/SCC verdicts | platform leg (RESULT.md E2) |
| `QCS-H12-vuln-image-in-use` | E1/E4/E5 — registry scan + vulnerability metadata | Qualys image scan — platform (RESULT.md) |
| `QCS-H13-image-lineage-drift` | E1/E2/E4 — image build history, digests, layer diff | Qualys registry scan — platform (RESULT.md) |
| `QCS-H14-file-hash` | E1/E2/E5 — image scan + hash search | platform scan; hash detection NOT supported at runtime (RESULT.md) |
| `QCS-H16-policy-enforcement` | E6 — net deactivation / memdump / pod kill / image blocklist | Qualys platform response actions (RESULT.md E6) |

Rule for all labs: if a hypothesis point has no live evidence, it MUST be
listed here AND in the lab's RESULT.md point table — never silently
dropped.

## Execution coverage matrix

One row per hypothesis execution point: the task, the policy that covers
it, and how it worked. New labs append rows here (skill rule).

| Lab | Point | Task | Policy | How it worked |
| --- | --- | --- | --- | --- |
| H01 | E1 | Restricted-v2 pod cannot access host path | — (admission) | Not covered live — `citi-h01-restricted` cannot start on the cluster (`CreateContainerConfigError`); path-level denial not demonstrated |
| H01 | E2 | Elevated pod, hostPath read-only | `pod.yaml` (hostPath `readOnly`) | Cluster: elevated pod ran, reads produced the v2 detection events |
| H01 | E3 | `ls, stat, cat, sha256sum` on host file | `policy-v2.yaml` v2 `read` (Postfix `/QCS-H01/canary.txt`) | `cat`/`sha256sum` → `vfs_read` events; `ls`/`stat` silent (correct) |
| H01 | E4 | ns/pod/container/process-tree/cmdline/path/node attribution | event fields | Verified: container, exec tree, cmdline, path, node, pod/ns in cluster runs |
| H01 | E5 | Delete pod → history searchable | — (retention) | Events persist after container removal |
| H02 | E1 | Drift create/write/metadata/rename/delete | `policy.yaml` (5 v2 file rules) | `security_inode_create`, `vfs_write`, `security_path_chmod`, `security_path_rename`, `security_path_unlink` all fired |
| H02 | E2 | Enforce: kill writer on block-dir write | `policy-enforce.yaml` `drift-block-write` | `KPROBE_ACTION_SIGKILL` at `vfs_write`, container exit 137 |
| H02 | E3 | Enforce: block exec of dropped script | `policy-enforce.yaml` `drift-block-exec` | `KPROBE_ACTION_SIGKILL` at `security_bprm_check`, script rc=137, container stable |
| H03 | E1 | Start shell (`oc exec` → docker exec) | base exec sensor | `process_exec /usr/bin/sh` (marker in argv) |
| H03 | E2 | Chain `bash → script → find/head` | `policy.yaml` `chain-exec` (v2 process rule) | Script exec flagged (`security_bprm_check`); children attributed to script |
| H03 | E3 | Short-lived + long-running children | base exec sensor | `find`/`head`/`sleep 2` + `sleep 300` — exec + exit each |
| H03 | E4 | Terminate selected processes | base exit sensor | killed `sleep 300` → `process_exit` with `signal: SIGTERM` |
| H03 | E5 | Launch/termination/parent/cmdline/UID/container/pod/ns | event fields | All verified; pod/ns in cluster runs |
| H04 | E1 | Inline `bash -c` | base exec sensor | Interpreter + **full script in argv** |
| H04 | E2 | Script via stdin | base exec sensor | Interpreter runs, argv `-` (body invisible) |
| H04 | E3 | File-read + network from inline script | `policy.yaml` `canary-open` + `egress-audit` | `security_file_open` on canary (8 events) + `tcp_connect` → :8080 |
| H04 | E4 | Interpreter/cmdline/children/associated activity | event fields + policy rules | **Partial (open event)** — everything visible except stdin script text |
| H04 | E5 | Compare with file-based script | base exec sensor | File script → binary = `/tmp/citi-h04-file.sh` (name visible) |
| H05 | E1 | Baseline connections to target service | `policy.yaml` egress audit (ports 8080+9090) | `tcp_connect` per request, `wget` attributed |
| H05 | E2 | Repeated requests via FQDN + ClusterIP | same | 6 `tcp_connect` events (name + IP → `172.20.0.2:8080`) |
| H05 | E3 | Successful + denied ports | same | :8080 success; denied :9090 recorded identically (`SYN_SENT`) |
| H05 | E4 | src process/workload, dst IP, port, protocol, namespace | event fields | wget, container id, dst IP, port, `IPPROTO_TCP` live; namespace k8s-only |
| H05 | E5 | Compare with OpenShift logs | — (platform) | Not covered live — no OpenShift logs in docker lab |
| H06 | E1 | Baseline to approved app dest | `policy.yaml` egress audit (80/443/8080) | `tcp_connect` → :8080 |
| H06 | E2 | Approved test dest on selected ports | same | `tcp_connect` → :443 (TLS fails; TCP recorded) |
| H06 | E3 | DNS then TCP/HTTP | `net-tcp-open` + native DNS event | both legs recorded — pod DNS to external resolver logged (`example.com` verified); kube-dns is next release |
| H06 | E4a | Blocked/unlisted port (:9090) | policy-scoped | **NO event** — outside `matchPorts` is invisible |
| H06 | E4b | Watched port, firewall-dropped | same | client rc=1 (blocked) but `tcp_connect` still recorded |
| H06 | E5 | addr/port/process/container/action telemetry | event fields | `tcp_connect`, `KPROBE_ACTION_POST`, container id |
| H07 | E1-E4 | Allow baseline, default-deny, repeat, compare | `policy.yaml` egress :8080 | blocked attempt rc=1 but `tcp_connect` identical to success |
| H07 | E5 | Attempt vs success vs no event | same | attempt reported; outcome not (H06/H07 pattern) |
| H08 | E1-E4 | Read payload, upload, repeat via script, correlate | `payload-open` + `egress-audit` | open+connect on same `wget`; script chains as parent |
| H08 | E5 | Contents not exposed | events | path + tuple only — never content |
| H09 | E1-E4 | Token read, authorized + unauthorized API queries | `sa-token-open` + `k8s-api-egress` | token/namespace opens (`cat`) + identical :6443 connects |
| H09 | E5 | Compare with API audit logs | — (platform) | not covered live |
| H10 | E1-E4 | Allowed + denied cross-ns API ops | same pair | token open + identical connects (authorized/denied/refused) |
| H10 | E5 | Audit logs for SA + authz result | — (platform) | not covered live |
| H11 | E1-E4 | Risky configs submitted; runtime context validated | v2 process rule (+ cap-change hook — **next release**) | execs flagged; capability-change matching needs a raw hook — next release |
| H11 | E5 | Admission vs runtime distinction | — (platform) | admission = SCC/OpenShift; runtime = exec events |
| H12 | E1-E4 | Scan, deploy, invoke in A not B, compare | v2 process rule on bash | A: 1 event; B: 0 — in-use signal |
| H12 | E5 | Image/pkg/version/remediation metadata | — (platform) | scan leg not covered live |
| H13 | E1-E5 | v1/v2 deploy, runtime change, diff layers vs runtime | FIM create/write/open | drift fully recorded; every FIM event is runtime (layers immutable) |
| H14 | E1-E5 | Scan, hash search, deploy, copy in, compare | path-only rules | hash not supported at runtime (blunt) — path-only evidence |
| H15 | E1-E5 | FIM lifecycle on suspicious filenames | 5 v2 file rules | create/write/rename/delete/open incl. child `sh` re-create |
| H16 | E1-E5 | Audit → enforce → re-execute → stability | audit + block process rules | rc=0 → rc=137 (SIGKILL at bprm), pod stable |
| H16 | E6 | Net deact / memdump / pod kill / image blocklist | — (platform) | not runtime-sensor capabilities |
| H17 | E1-E5 | Sequence, record IDs, delete, search, reconstruct | payload-open + egress | 13 events survive deletion (7 policy-matched) |
| H18 | E1-E6 | Chain: script→exec→read→DNS→connect→reconstruct | process + file + egress (+ kube-dns leg — **next release**) | chain joins by exec_id/marker; 1.8 logs pod DNS to external resolvers, kube-dns next release; no built-in sequence view |
| H19 | E1-E5 | Health, workloads, interruption, degraded, recovery | probe rule | baseline 1 → outage 0 → recovery 1 |

## Lab run log

### 2026-11-03 — H07–H19 full pass (all remaining hypotheses)

Change done: point-by-point tables + observed events added to all 13
RESULT.mds; README coverage matrix extended to H19; not-covered rows added.

Summary of live results (policy → evidence):

| Lab | Evidence |
| --- | --- |
| H07 | blocked attempt (iptables DROP) recorded identically to success |
| H08 | payload open + upload correlated on same `wget`; contents never captured |
| H09 | token/namespace opens + API connects; bonus: caught minikube storage-provisioner's real token read |
| H10 | authorized/denied/refused connects — identical events |
| H11 | execs flagged; capability-change matching is a next-release item |
| H12 | A: 1 bash event, B: 0 — in-use signal |
| H13 | drift create/write/open fully recorded |
| H14 | path-only; no hash fields (not supported — blunt) |
| H15 | full FIM lifecycle incl. child re-create |
| H16 | audit rc=0 → enforce rc=137 (SIGKILL), pod stable |
| H17 | 13 events survive container deletion (7 policy-matched) |
| H18 | chain bash→payload→script→cat→connect reconstructs; kube-dns leg is next release (1.8 logs pod DNS to external resolvers natively) |
| H19 | baseline 1 → outage 0 → recovery 1 (agent restarted identically) |

Note: the H19 outage test killed and restarted the agent; it was brought
back with the same configuration and the event capture reconnected.

### 2026-11-03 — H06 quick run (north-south visibility)

Change done: H06 RESULT point table (S1–S5, E1–E5) + observed events;
README matrix rows + not-covered row (S3).

What the sensor recorded (policy `citi-h06-north-south`):

- Baseline :8080, test dest :443, and firewall-dropped :8080 all recorded
  (the attempt, not the outcome — client rc=1 on the dropped one, event still
  posted). Unlisted port :9090 → no event (policy-scoped).
- Action telemetry present (`KPROBE_ACTION_POST`).
- The DNS leg (UDP :53): agent 1.8 logs DNS natively
  (`MSG_OP_QUALYS_DNS`), including pod lookups to external resolvers —
  kube-dns (cluster-internal) is the **next-release** gap; the raw
  policy was removed from the lab.

### 2026-11-03 — H05 quick run (east-west visibility)

Change done: H05 RESULT point table (S1–S5, E1–E5) + observed events;
README matrix rows added; policy updated to add the denied port 9090.

Detection events observed (policy `citi-h05-east-west`, client `citi-client`):

```json
{"process_kprobe": {"policy_name": "citi-h05-east-west-v2-east-west-egress", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/wget", "docker": "dfd56b3f3564"},
 "args": [{"sock_arg": {"daddr": "172.20.0.2", "dport": 8080, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}]}}
{"process_kprobe": {"policy_name": "citi-h05-east-west-v2-east-west-egress", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/wget"},
 "args": [{"sock_arg": {"daddr": "172.20.0.2", "dport": 9090, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}]}}
```

- Baseline + repeated (FQDN + ClusterIP-equiv) + denied port all recorded with
  src process, workload, dst IP, port, protocol. Denied = identical event
  (attempt, not outcome). Denied ports are policy-scoped (9090 added).
- Cluster noise observed: minikube coredns/kubelet health probes to :8080
  also matched — deployment scoping caveat recorded in RESULT.
- Policy + containers + network deleted after the run.

### 2026-11-03 — H04 quick run (fileless / inline script execution)

Change done: H04 RESULT.md gained the point-by-point table (E1–E5) +
observed events (cases 1–3).

Detection events observed (policy `citi-h04-fileless-exec`):

```json
// case 1 — inline `bash -c` (marker CITI-H04-inline): full argv visible
{"process_exec":   {"process": {"binary": "/usr/bin/bash", "arguments": "-c \"echo CITI-H04-inline; cat /etc/citi-h04-canary.txt; exec 3<>/dev/tcp/172.17.0.1/8080\""}}}
{"process_kprobe": {"policy_name": "citi-h04-fileless-exec-v2-canary-open", "function_name": "security_file_open", "process": {"binary": "/usr/bin/cat"}}}
{"process_kprobe": {"policy_name": "citi-h04-fileless-exec-v2-egress-audit", "function_name": "tcp_connect", "process": {"binary": "/usr/bin/bash"}}}

// case 2 — stdin-fed script (marker CITI-H04-stdin): argv = "-" (body invisible)
{"process_exec":   {"process": {"binary": "/usr/bin/bash", "arguments": "-"}}}
{"process_kprobe": {"policy_name": "citi-h04-fileless-exec-v2-canary-open", "function_name": "security_file_open", "process": {"binary": "/usr/bin/cat"}}}
{"process_kprobe": {"policy_name": "citi-h04-fileless-exec-v2-egress-audit", "function_name": "tcp_connect", "process": {"binary": "/usr/bin/bash"}}}

// case 3 — file-based script: binary IS the script path
{"process_exec":   {"process": {"binary": "/tmp/citi-h04-file.sh", "arguments": "/tmp/citi-h04-file.sh"}}}
```

- Interpreter + cmdline (for `-c`) + children + file-open + network activity all
  captured; stdin script body invisible (argv `-`) — matches the
  "[Partial (Open event)]" annotation. File-based scenario shows the script
  path as the binary.
- Policy + container deleted after the run.

### 2026-11-03 — H03 quick run (suspicious process lineage)

Change done: H03 RESULT.md gained the point-by-point table (E1–E5, per the
skill rule) + observed events; README not-covered list updated (E5g).

Detection events observed (policy `citi-h03-process-lineage`, marker `CITI-H03-5521`):

```json
{"process_exec":   {"process": {"binary": "/usr/bin/sh", "arguments": "-c \"MARKER=CITI-H03-5521 …\"", "uid": 0, "docker": "c487a1d85fed"}}}
{"process_kprobe": {"policy_name": "citi-h03-process-lineage-v2-chain-exec", "function_name": "security_bprm_check"}}
{"process_exec":   {"process": {"binary": "/tmp/citi-h03-chain.sh", "parent": {"binary": "/usr/bin/sh"}}}}
{"process_exec":   {"process": {"binary": "/usr/bin/sleep", "arguments": "300", "parent": {"binary": "/tmp/citi-h03-chain.sh"}}}}
{"process_exec":   {"process": {"binary": "/usr/bin/find", "arguments": "/etc -name *.conf", "parent": {"binary": "/tmp/citi-h03-chain.sh"}}}}
{"process_exec":   {"process": {"binary": "/usr/bin/head", "arguments": "-3", "parent": {"binary": "/tmp/citi-h03-chain.sh"}}}}
{"process_exit":   {"process": {"binary": "/usr/bin/head"}, "signal": null}}
{"process_exit":   {"process": {"binary": "/usr/bin/find"}, "signal": null}}
{"process_exit":   {"process": {"binary": "/usr/bin/sleep", "arguments": "300"}, "signal": "SIGTERM"}}
```

- Full chain recorded: launch + exit for every process, parent on every event,
  command line, UID, container id. Terminated process's exit carries
  `signal: SIGTERM`. Pod/namespace fields are k8s-only (E5g not covered live).
- Policy deleted after the run.

### 2026-11-03 — H02 quick run (audit + enforce) and execution-point coverage

Change done:

- Added "Execution-point coverage" section (this README) + mandatory point-by-point
  tables in RESULT.md (skill rule) — H01 table updated to the original
  hypothesis execution flow (E1–E5); not-covered points listed above.
- Environment note: the event capture was restarted fresh for the lab
  run (`/tmp/citi-labs/events.jsonl`).

H02 runtime file drift — detection events observed (policy `citi-h02-file-drift`):

```json
{"process_kprobe": {"policy_name": "citi-h02-file-drift-v2-drift-create",   "function_name": "security_inode_create",  "process": {"binary": "/usr/bin/bash"}}}
{"process_kprobe": {"policy_name": "citi-h02-file-drift-v2-drift-write",    "function_name": "vfs_write",             "process": {"binary": "/usr/bin/bash"}}}
{"process_kprobe": {"policy_name": "citi-h02-file-drift-v2-drift-metadata", "function_name": "security_path_chmod",   "process": {"binary": "/usr/bin/chmod"}}}
{"process_kprobe": {"policy_name": "citi-h02-file-drift-v2-drift-rename",   "function_name": "security_path_rename", "process": {"binary": "/usr/bin/mv"}}}
{"process_kprobe": {"policy_name": "citi-h02-file-drift-v2-drift-delete",   "function_name": "security_path_unlink", "process": {"binary": "/usr/bin/rm"}}}
```

Enforce mode (policy `citi-h02-file-drift-enforce`, `action: block`):

```json
{"process_kprobe": {"policy_name": "citi-h02-file-drift-enforce-v2-drift-block-write", "function_name": "vfs_write",            "process": {"binary": "/usr/bin/bash"}, "action": "KPROBE_ACTION_SIGKILL"}}
{"process_kprobe": {"policy_name": "citi-h02-file-drift-enforce-v2-drift-block-exec",  "function_name": "security_bprm_check", "process": {"binary": "/usr/bin/bash"}, "action": "KPROBE_ACTION_SIGKILL"}}
```

- Audit: all 5 drift operations detected with process attribution.
- Enforce: write under the block dir → SIGKILL at the hook (container exit 137);
  exec of the dropped script → SIGKILL at `security_bprm_check` (script rc=137,
  container stayed stable).
- Policies deleted after the run; capture left running.

## Field gotchas (learned from running these)

- **Path filters match the container's view** — `matchFilePaths`/
  `matchBinaries` evaluate the path as resolved in the workload's mount
  namespace; mount the target at the same absolute path the policy
  expects (QCS-H01).
- **Path filters match the RESOLVED path** — symlinks are followed
  before matching: `/var/run` → `/run`, so a SA-token mount reports
  `/run/secrets/kubernetes.io/serviceaccount/…`. List both prefixes or
  use a Postfix on the stable tail (QCS-H09).
- **`tcp_connect` records attempts, not outcomes** — the event fires at
  SYN-send; refused, dropped, and successful connects look identical
  (ret=0). Success/denial needs platform network logs (QCS-H06/H07).
- **`action: block` = SIGKILL the process** — exit 137, not a clean
  "permission denied" (QCS-H02).
- **stdin-fed scripts leave no script content** — only the interpreter
  launch plus its child/file/network activity (QCS-H04).
- **`pod`/`namespace` fields populate under k8s/OpenShift — verified in
  cluster runs**; non-k8s runtimes show the container id only (H03/H05).
- **Per-rule policies** are named `<policy>-v2-<rule-id>` — delete all
  of a v2 policy's rules when removing it.
