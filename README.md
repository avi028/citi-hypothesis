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
All nineteen labs also carry verified `policy-v1.yaml` (legacy v1
schema); `ALL-HYPOTHESES.md` consolidates both policy forms + observed
data, plus the three "discuss with Qualys" use cases (crypto-mining —
mechanism verified in `tools/miner-sim.yaml`; package search;
unauthorized components).

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
- **`pod`/`namespace` fields only populate under k8s** — plain docker
  shows the `docker` container id only (H03/H05).
- **Per-rule policies** are named `<policy>-v2-<rule-id>`; remove them
  with `tetra tracingpolicy delete <policy> --all-rules`.
