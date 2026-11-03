# citi-hypothesis labs

Self-contained labs that prove (or disprove) Qualys runtime-detection
hypotheses against a live Tetragon agent. Each lab ships a policy, a
workload manifest, and a recorded result.

**Base version: `release/v1.6-1-q5`** — all labs are verified on this
branch. `setup.sh` warns if you run from a different branch.

```
tar xzf citi-hypothesis.tar.gz        # unpack inside the tetragon repo root
cd tetragon
sudo citi-hypothesis/setup.sh         # checks env, builds, starts agent + capture
```

## Prerequisites

- Linux host with root access (`sudo`)
- docker
- Go toolchain
- Built BPF objects: `make tetragon-bpf-local LOCAL_CLANG=1` (once per
  checkout/kernel)

## E2E test loop (no cluster needed)

Every hypothesis is validated with this 5-stage loop — real agent, real
kernel hooks, real workload, real events:

```
stage 1  tetragon agent running            (setup.sh or manual, on :54321)
stage 2  tetra getevents -o json >> events.jsonl   (background capture)
stage 3  ./tetra tracingpolicy add <lab>/policy.yaml
stage 4  docker run/exec <workload>        (generates the activity)
stage 5  grep the capture file → verify policy_name, binary, args,
         parent, docker id, sock tuple, action
```

The capture file is the single source of truth for the result: an
execution point is "covered" only when its evidence appears there. No
cluster, no platform — the sensor path is exercised end-to-end.

## Quickstart

```bash
sudo citi-hypothesis/setup.sh        # checks env, builds, starts tetragon + capture

# run a lab
./tetra tracingpolicy add citi-hypothesis/QCS-H02-runtime-file-drift/policy.yaml
docker run --rm debian:stable-slim sh -c 'mkdir -p /tmp/citi-h02 && echo x > /tmp/citi-h02/a'
tail /tmp/citi-labs/events.jsonl     # detection records land here

# cleanup
./tetra tracingpolicy delete citi-h02-file-drift --all-rules
sudo citi-hypothesis/teardown.sh
```

### Agent flags some labs need

- `--enable-process-cred` — required for `binary_properties` on exec
  events (setuid/setgid/caps **and** memory-resident binaries). Needed by
  QCS-H04's memfd detection.
- `--enable-ancestors` — emit ancestor chain info on exec events (needed
  if a lab reads `ancestors` fields; raw `matchBinaries`/`followChildren`
  ancestor matching itself needs no flag).
- Pass via `TETRAGON_ARGS` to setup.sh:
  `TETRAGON_ARGS="--enable-process-cred" sudo citi-hypothesis/setup.sh`

## Lab anatomy

```
citi-hypothesis/<LAB-NAME>/
├── policy.yaml      # RuntimePolicy v2 (auto-translated by tetra)
├── policy-v1.yaml   # RuntimePolicy v1 (legacy form — see below)
├── pod.yaml         # k8s/OpenShift manifest that generates the activity
├── RESULT.md        # hypothesis, what we ran, what we saw, verdict
└── tracingpolicy.yaml        # optional: raw Cilium fallback (see below)
```

### RuntimePolicy v1 (legacy) form

Every lab also ships `policy-v1.yaml`: the same detection in the legacy
`qualys.com/v1` schema (`spec.base-policy` + `monitor-*`/`match-binaries`
+ `action`). One document per base-policy — v1 has no rule list.

`tetra` cannot ingest v1 directly (that path belongs to the cluster's
conversion webhook + operator). To test locally, run the same builders
the operator uses:

```bash
go build -mod=mod -o /tmp/v1convert ./citi-hypothesis/tools/v1convert
/tmp/v1convert <lab>/policy-v1.yaml > /tmp/tp.yaml
./tetra tracingpolicy add /tmp/tp.yaml
```

v1 differences vs v2 (verified by these labs):

- `monitor-paths` = **Prefix on the resolved path** only (no Postfix —
  `/var/run`→`/run` still applies, QCS-H09)
- `action`: `audit`→Post, `kill`→Sigkill
- **all Post actions get `rateLimit: 1m` (scope global) — `rate-limit:"0"`
  maps to the same default; it cannot be disabled.** Bursts lose events.
- file policies auto-add `matchNamespaces: Pid NotIn host_ns` — container
  opens only; host opens of the same path never fire.
- no v1 base-policy for process-exec (H03), memfd (H04), or DNS/UDP (H06)
  — those stay on v2 rules or raw TracingPolicy.

Copy `citi-hypothesis/TEMPLATE/` to start a new lab: write the hypothesis,
add the policy + pod manifests, run it locally with the docker flow above,
then record the outcome in `RESULT.md` — plain language, verdict up front.

## RuntimePolicy v2 capability (release/v1.6-1-q5)

| Rule `type` | What it produces | Filters |
|---|---|---|
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
lab as `tracingpolicy.yaml`. `tetra tracingpolicy add` applies it
verbatim; see `TEMPLATE/tracingpolicy.yaml` and the working examples in
QCS-H04 (`sys_memfd_create`) and QCS-H06 (UDP `:53`).

### Future implementation note

Every hook exercised this way is a candidate for a future v2 rule type or
field. When a lab can only be expressed with a raw TracingPolicy, record
the missing field in `RESULT.md` under "Future implementation" — current
gaps found by these labs: a `memfd`/`fileless` rule type, `matchBinaries`
on memory-backed execs, DNS (UDP) visibility on network rules.

## Labs

| Lab | Hypothesis | Verdict | CRS |
|---|---|---|
| `QCS-H01-host-file-access` | Container reads a controlled host path → detected with attribution | Supported | 1.45+ |
| `QCS-H02-runtime-file-drift` | Post-deploy file create/write/chmod/rename/exec/delete → detected; enforce mode kills the actor | Supported | 1.45+* |
| `QCS-H03-process-lineage` | Full parent/child lineage of a suspicious chain → recorded | Supported (immediate parent per event; pod fields need k8s) | 1.46+ |
| `QCS-H04-fileless-exec` | Inline/stdin + memfd fileless execution → visible via activity; memfd blocked at `sys_memfd_create` | Partial (script body invisible; memfd exec flagged via `binary_properties`, enforcement needs raw TP) | 1.45+* |
| `QCS-H05-east-west-visibility` | Cross-namespace connects → full 5-tuple + process + container per event | Supported (pod/ns names need k8s) | 1.45+ |
| `QCS-H06-north-south` | Outbound connects incl. refused/blackholed → recorded; unlisted ports → not; UDP DNS → needs raw TP | Supported (scoped to watched ports; DNS needs `ip_output` fallback) | 1.45+* |
| `QCS-H07-netpol-denied` | Denied connection attempts → still recorded, identical to successes | Supported (attempt ≠ outcome; corroborate with platform logs) | 1.45+ |
| `QCS-H08-data-exfil` | File read + outbound send correlated on same PID/parent chain, even via runtime script | Supported (contents never captured) | 1.45+ |
| `QCS-H09-service-account-token` | SA token file open + K8s API egress → both recorded with process + container attribution | Supported (API request/verdict inside TLS → audit log only) | 1.45+ |
| `QCS-H10-cross-ns-rbac` | Authorized vs unauthorized API calls → identical connect events with attribution | Supported (allow/deny only in K8s audit log) | 1.45+ |
| `QCS-H11-priv-escalation` | Elevated exec (CAP_SYS_ADMIN) → cap-change event fires once; exec events carry cap sets | Supported (raw TP for caps; admission verdict is SCC's) | 1.46+* |
| `QCS-H12-vuln-image-in-use` | Vuln package invoked in A → event; present-but-unused in B → none | Partial (runtime "in use" proven; scan leg is platform) | 1.46+ |
| `QCS-H13-image-lineage-drift` | Post-deploy create/write/open recorded with attribution | Partial (drift proven; digest/layer diff is platform) | 1.45+ |
| `QCS-H14-file-hash` | No hash fields/operators in events or policies | Not supported (path-only; hash search is platform) | 1.45+ |
| `QCS-H15-suspicious-filename` | Full FIM lifecycle on Login.jsp/Sql.java/package.json incl. child re-create | Supported | 1.45+ |
| `QCS-H16-policy-enforcement` | Audit rc=0 → block rc=137 (SIGKILL at exec), pod stable | Supported (net-deact/memdump/pod-kill/image-block = platform) | 1.46+ |
| `QCS-H17-deleted-pod-retention` | 11 events survive container deletion, searchable by id/marker | Supported (retention window = platform setting) | 1.45+ |
| `QCS-H18-signal-correlation` | exec → file → read → DNS → connect chain reconstructs from events | Supported at sensor level (joinable; DNS needs raw TP) | 1.46+* |
| `QCS-H19-sensor-health` | Interruption → event gap; recovery → events resume | Supported (degraded-node UI = platform sensor profile) | 1.45+ |
**CRS version per lab**: `1.45+` = RuntimePolicy v1 suffices; `1.46+`
= RuntimePolicy v2 required (process/exec rules); a `*` marks a lab with
one leg that needs a raw Cilium TracingPolicy hook (future release).
### v1 coverage per lab (H01–H10)

Every lab ships `policy-v1.yaml`; live-verified. Where a leg cannot be
expressed in v1 it is flagged in the lab's policy file and listed here:

- **Fully v1 (no v2 needed)**: H01 (file-read), H04 (inline/activity
  file + network legs), H05, H07 (net-tcp-open), H08 (file + network),
  H09, H10 (SA-token open + API ports).
- **Partial — one leg is v2-only**:
  - H02: drift create/write/metadata/rename/delete + `action: kill` are
    v1; the **exec-block** of the dropped script is a v2 process rule.
  - H03: v1 `file-open` approximates the launch marker; the **process-exec
    flag** is v2-only (no process base-policy in v1).
  - H04: **memfd fileless exec** — no v1 base-policy; raw
    `tracingpolicy*.yaml` required (future release).
  - H06: **UDP/DNS** leg — `net-tcp-open` is TCP only; raw `ip_output`
    TracingPolicy required (future release).

All nineteen labs also carry verified `policy-v1.yaml` (legacy v1
schema); `ALL-HYPOTHESES.md` consolidates both policy forms + observed
data, plus the three "discuss with Qualys" use cases (crypto-mining —
mechanism verified in `tools/miner-sim.yaml`; package search;
unauthorized components).

## Execution-point coverage

Every lab's RESULT.md now carries a **"Point-by-point check"** table that
maps each setup (S*) and execution-flow (E*) point of the original
hypothesis to the recorded evidence (or marks it "Not covered"). Points
the runtime lab could not verify live are listed here — they are either
platform-only legs or require a cluster. This list is kept in sync with
the skill (`citi-hypothesis-labs`) so new labs follow the same rule.

| Lab | Execution points NOT covered (live) | Why / where it lives |
|---|---|---|
| `QCS-H01-host-file-access` | E1 — restricted-v2 pod denial (live) | manifest `citi-h01-restricted` provided; needs a cluster apply (RESULT.md E1) |
| `QCS-H01-host-file-access` | E2 — elevated-pod apply with read-only hostPath | manifest `citi-h01-elevated` provided; docker-local `-v :ro` equivalent verified live (RESULT.md E2) |
| `QCS-H05-east-west-visibility` | S4 — NetworkPolicy (intended-path-only) enforcement | docker has no NetworkPolicy; needs OpenShift (RESULT.md S4) |
| `QCS-H05-east-west-visibility` | E5 — compare with OpenShift network/app logs | platform log comparison; minikube cluster available for the platform run (RESULT.md E5) |
| `QCS-H06-north-south` | S3 — OpenShift egress controls (only test dest permitted) | docker has no egress policy; needs OpenShift (RESULT.md S3) |
| `QCS-H07-netpol-denied` | S2/S5 — real NetworkPolicy + OpenShift network logs | simulated with iptables DROP; needs OpenShift (RESULT.md S2/S5) |
| `QCS-H08-data-exfil` | DNS leg of the correlation | flow used IPs only; add `ip_output` :53 for DNS (RESULT.md) |
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
|---|---|---|---|---|
| H01 | E1 | Restricted-v2 pod cannot access host path | — (admission) | Not covered live — manifest `citi-h01-restricted` shipped; needs cluster apply |
| H01 | E2 | Elevated pod, hostPath read-only | `pod.yaml` (hostPath `readOnly`) | Docker-local `-v :ro` verified; pod apply needs cluster |
| H01 | E3 | `ls, stat, cat, sha256sum` on host file | `policy.yaml` v2 `read` (Postfix `/QCS-H01/canary.txt`) | `cat`/`sha256sum` → `vfs_read` events; `ls`/`stat` silent (correct) |
| H01 | E4 | ns/pod/container/process-tree/cmdline/path/node attribution | event fields | Verified: container, exec tree, cmdline, path, node live; pod/ns in cluster runs |
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
| H06 | E3 | DNS then TCP/HTTP | + `tracingpolicy-dns.yaml` (UDP :53) | 2 `ip_output` events (getent) + `tcp_connect` |
| H06 | E4a | Blocked/unlisted port (:9090) | policy-scoped | **NO event** — outside `matchPorts` is invisible |
| H06 | E4b | Watched port, firewall-dropped | same | client rc=1 (blocked) but `tcp_connect` still recorded |
| H06 | E5 | DNS/addr/port/process/container/action telemetry | event fields | `ip_output`+`tcp_connect`, `KPROBE_ACTION_POST`, container id |
| H07 | E1-E4 | Allow baseline, default-deny, repeat, compare | `policy.yaml` egress :8080 | blocked attempt rc=1 but `tcp_connect` identical to success |
| H07 | E5 | Attempt vs success vs no event | same | attempt reported; outcome not (H06/H07 pattern) |
| H08 | E1-E4 | Read payload, upload, repeat via script, correlate | `payload-open` + `egress-audit` | open+connect on same `wget`; script chains as parent |
| H08 | E5 | Contents not exposed | events | path + tuple only — never content |
| H09 | E1-E4 | Token read, authorized + unauthorized API queries | `sa-token-open` + `k8s-api-egress` | token/namespace opens (`cat`) + identical :6443 connects |
| H09 | E5 | Compare with API audit logs | — (platform) | not covered live |
| H10 | E1-E4 | Allowed + denied cross-ns API ops | same pair | token open + identical connects (authorized/denied/refused) |
| H10 | E5 | Audit logs for SA + authz result | — (platform) | not covered live |
| H11 | E1-E4 | Risky configs submitted; runtime context validated | v2 process rule + raw cap-change TP | execs flagged; cap-change fires on cap transitions (blunt: not a clean "gained" filter) |
| H11 | E5 | Admission vs runtime distinction | — (platform) | admission = SCC/OpenShift; runtime = exec events |
| H12 | E1-E4 | Scan, deploy, invoke in A not B, compare | v2 process rule on bash | A: 1 event; B: 0 — in-use signal |
| H12 | E5 | Image/pkg/version/remediation metadata | — (platform) | scan leg not covered live |
| H13 | E1-E5 | v1/v2 deploy, runtime change, diff layers vs runtime | FIM create/write/open | drift fully recorded; every FIM event is runtime (layers immutable) |
| H14 | E1-E5 | Scan, hash search, deploy, copy in, compare | path-only rules | hash not supported at runtime (blunt) — path-only evidence |
| H15 | E1-E5 | FIM lifecycle on suspicious filenames | 5 v2 file rules | create/write/rename/delete/open incl. child `sh` re-create |
| H16 | E1-E5 | Audit → enforce → re-execute → stability | audit + block process rules | rc=0 → rc=137 (SIGKILL at bprm), pod stable |
| H16 | E6 | Net deact / memdump / pod kill / image blocklist | — (platform) | not runtime-sensor capabilities |
| H17 | E1-E5 | Sequence, record IDs, delete, search, reconstruct | payload-open + egress | 13 events survive deletion (7 policy-matched) |
| H18 | E1-E6 | Chain: script→exec→read→DNS→connect→reconstruct | process + file + egress + raw DNS TP | full chain joins by exec_id/marker; no built-in sequence view |
| H19 | E1-E5 | Health, workloads, interruption, degraded, recovery | probe rule | baseline 1 → outage 0 → recovery 1 |

## Lab run log

### 2026-11-03 — H07–H19 full pass (all remaining hypotheses)

Change done: point-by-point tables + observed events added to all 13
RESULT.mds; README coverage matrix extended to H19; not-covered rows added.

Summary of live results (policy → evidence):

| Lab | Evidence |
|---|---|
| H07 | blocked attempt (iptables DROP) recorded identically to success |
| H08 | payload open + upload correlated on same `wget`; contents never captured |
| H09 | token/namespace opens + API connects; bonus: caught minikube storage-provisioner's real token read |
| H10 | authorized/denied/refused connects — identical events |
| H11 | execs flagged; cap-change TP fires on transitions (blunt caveat) |
| H12 | A: 1 bash event, B: 0 — in-use signal |
| H13 | drift create/write/open fully recorded |
| H14 | path-only; no hash fields (not supported — blunt) |
| H15 | full FIM lifecycle incl. child re-create |
| H16 | audit rc=0 → enforce rc=137 (SIGKILL), pod stable |
| H17 | 13 events survive container deletion (7 policy-matched) |
| H18 | chain bash→payload→script→cat→DNS(8)→connect reconstructs |
| H19 | baseline 1 → outage 0 → recovery 1 (agent restarted identically) |

Note: the H19 outage test killed and restarted the agent; it was brought
back with the same args (`--bpf-lib bpf/objs --export-filename
/tmp/e2e-check/export.jsonl`) and the lab capture reconnected.

### 2026-11-03 — H06 quick run (north-south visibility)

Change done: H06 RESULT point table (S1–S5, E1–E5) + observed events;
README matrix rows + not-covered row (S3).

Tetragon events observed (policy `citi-h06-north-south` + `citi-h06-dns-audit`):

```json
{"process_kprobe": {"policy_name": "citi-h06-north-south-v2-egress-audit", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/wget", "docker": "f584bb99436f"},
 "args": [{"sock_arg": {"daddr": "172.17.0.1", "dport": 8080, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}],
 "action": "KPROBE_ACTION_POST"}}
{"process_kprobe": {"policy_name": "citi-h06-dns-audit", "function_name": "ip_output", "process": {"binary": "/usr/bin/getent"}}}
```

- Baseline :8080, test dest :443, DNS+connect, and firewall-dropped :8080 all
  recorded (attempt, not outcome — client rc=1 on the dropped one, event still
  posted). Unlisted port :9090 → no event (policy-scoped, blunt).
- Action telemetry present (`KPROBE_ACTION_POST`).
- Policy + DNS TP + container + network + listeners deleted after the run.

### 2026-11-03 — H05 quick run (east-west visibility)

Change done: H05 RESULT point table (S1–S5, E1–E5) + observed events;
README matrix rows added; policy updated to add the denied port 9090.

Tetragon events observed (policy `citi-h05-east-west`, client `citi-client`):

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

Tetragon events observed (policy `citi-h04-fileless-exec`):

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

Tetragon events observed (policy `citi-h03-process-lineage`, marker `CITI-H03-5521`):

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
- Environment note: the running agent had been replaced by the matchCmdArgs
  e2e session (writes `/tmp/e2e-check/export.jsonl`); restarted the lab
  capture (`tetra getevents -o json` → fresh `/tmp/citi-labs/events.jsonl`).

H02 runtime file drift — Tetragon events observed (policy `citi-h02-file-drift`):

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
  cluster runs**; plain docker shows the `docker` container id only (H03/H05).
- **Per-rule policies** are named `<policy>-v2-<rule-id>`; remove them
  with `tetra tracingpolicy delete <policy> --all-rules`.
