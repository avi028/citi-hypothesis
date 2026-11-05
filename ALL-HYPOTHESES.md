# citi-hypothesis — All Labs Summary (H01–H20)

Consolidated reference for every hypothesis lab: the hypothesis in plain
language, the workload manifest (`pod.yaml`), the detection policy in both
RuntimePolicy **v2** (`policy.yaml`) and **v1** (`policy-v1.yaml`) form,
the **CRS version** each lab needs, and the recorded verdict with observed
data. Each lab's full write-up lives in its own `RESULT.md`.

Base version: `release/v1.6-1-q5`.

## v1 vs v2 — form notes

- **v1 = one CR per base-policy** (no rule list). `base-policy` values:
  `file-open|file-read|file-write|file-write-diff|file-create|file-delete|
  file-rename|file-metadata|file-links`, `net-tcp-open`, `qualys-*`.
- `monitor-paths` are **Prefix-matched on the resolved path** (symlinks
  resolved — `/var/run` → `/run`); there is no Postfix operator in v1.
- `action`: `audit`→Post, `kill`→Sigkill.
- **Every v1 Post action is rate-limited to 1m/global when unset — and
  `rate-limit: "0"` maps to the same default, so it cannot be disabled.**
  Bursts get throttled. v2 has no such limit.
- v1 file policies auto-add `matchNamespaces: Pid NotIn host_ns` — they
  fire on container opens only, never host opens of the same path.
- No v1 base-policy for process-exec, capabilities, memfd, DNS/UDP, or
  custom hooks — those need v2 process rules or raw TracingPolicy.
- `ebpf-operator tracingpolicy add` cannot ingest v1 YAML directly — the cluster
  converts it via the v1→v2 webhook; locally, `tools/v1convert` runs the
  same `controllers.Create*Policy` builders to emit the TracingPolicy.

### v1 live-test results (verified on the running agent)

| Lab | v1 policies loaded | What fired |
|---|---|---|
| H01 | `file-read` | `vfs_read` event on the mounted canary |
| H02 | 5 file base-policies + `file-write kill` | all 5 hooks fired; enforce → SIGKILL rc=137 |
| H03 | `file-open` on chain script | open at launch (v1 launch marker) |
| H04 | `file-open` canary + `net-tcp-open` | open + connect events |
| H05 | `net-tcp-open` :8080 | `tcp_connect` with tuple + attribution |
| H06 | `net-tcp-open` 80/443/8080 | allowed/refused/blackholed recorded; :9090 silent |
| H07 | `net-tcp-open` :8080 | denied attempt recorded identically |
| H08 | `file-open` + `net-tcp-open` :8080 | open + connect on same chain |
| H09 | `file-open` SA dir + `net-tcp-open` 443/6443 | token opens + API connect |
| H10 | `file-open` SA dir + `net-tcp-open` 443/6443 | identical events for allow/deny/refused |
| H11–H14, H16–H19 | converted + load-verified | v2-verified live; v1 builder path proven |
| H15 | 5 v1 file base-policies | spot-checked live — all 5 hooks fired |

### v1 gaps vs v2 (what v1 cannot express)

- **Process exec / enforcement of exec** — no base-policy (H03, H12,
  H16: exec-block leg v2-only).
- **Capabilities** (H11) — no capability filter; v2 needs raw TP too.
- **memfd fileless exec** (H04) — raw TracingPolicy required.
- **DNS/UDP** (H06, H18) — `net-tcp-open` is TCP connect only.
- **Burst fidelity** — forced `rateLimit: 1m` drops repeated events.


## CRS version support (per lab)

- **1.45+** — fully covered by RuntimePolicy **v1** (no v2 needed)
- **1.46+** — requires RuntimePolicy **v2** (process rules, exec context,
  enforcement) — v1 cannot express it
- **future release** — needs a **raw Cilium TracingPolicy** hook that v2
  does not have (caps, memfd, UDP/DNS, custom hooks); also recorded under
  "Future implementation" in the RESULT.md of the affected lab

| Lab | Hypothesis (one line) | Verdict (v2) | CRS | v1 verified |
|---|---|---|---|---|
| `QCS-H01-host-file-access` | Container Escape / Host File Access Attempt | **Requires RuntimePolicy v2.** The hypothesis scopes to a specific host file via the v2 `Postfix` operator; v1 has no Postfix (Prefix-only), so v1 cannot determine the host file | 1.46+ | no |
| `QCS-H02-runtime-file-drift` | Runtime File Drift and Unauthorized Executable Creation | **It works, in both modes.** Every stage of the file's life produced a detection record. I | 1.45+ | yes |
| `QCS-H03-process-lineage` | Suspicious Process and Parent-Child Process Detection | **Supported, with one honest "partial".** Every launch, every child, every termination was | 1.46+ | yes |
| `QCS-H04-fileless-exec` | Fileless or Inline Script Execution | **Partially — and the partial part matters.** You can't see the fileless script *itself*,  | 1.45+ | yes |
| `QCS-H05-east-west-visibility` | Cross-Namespace East-West Communication Visibility | **It works.** Every connection produced a record with the source program, source IP, desti | 1.45+ | yes |
| `QCS-H06-north-south` | Unusual North-South Network Connection | **It works.** Successful, refused, and blackholed connections were all recorded with proce | 1.45+ | yes |
| `QCS-H07-netpol-denied` | Network Policy Violation and Denied Connection Attempt | **The attempt is recorded, always.** Qualys sees the connection the moment it is initiated | 1.45+ | yes |
| `QCS-H08-data-exfil` | Controlled Data Transfer / Exfiltration Simulation | **It works — the correlation is exact.** The file-open event and the outbound-connection e | 1.45+ | yes |
| `QCS-H09-service-account-token` | Service Account Token Access and Kubernetes API Activity | **Supported.** The token-file opens and the API connection were both recorded, each carryi | 1.45+ | yes |
| `QCS-H10-cross-ns-rbac` | Cross-Namespace RBAC Access Attempt | **Supported for visibility; the allow/deny verdict is not Qualys's job.** Every API-bound  | 1.45+ | yes |
| `QCS-H11-priv-escalation` | Privilege Escalation Configuration Detection | **Supported for runtime context; the pod-spec admission verdict is a separate concern.** W | 1.46+ | yes |
| `QCS-H12-vuln-image-in-use` | Vulnerable Image Discovery and "In Use" Prioritization | **Partial — and the split is clean.** The registry side (vuln discovery, CVSS, fix version | 1.46+ | yes |
| `QCS-H13-image-lineage-drift` | Image Lineage and Runtime Integrity Change | **Partial — image lineage is platform data, runtime drift is sensor data.** The runtime si | 1.45+ | yes |
| `QCS-H14-file-hash` | Malicious or Test File Hash Detection | **Not supported by the runtime sensor.** Verified two ways: (1) by inspection — no hash op | 1.45+ | yes |
| `QCS-H15-suspicious-filename` | Suspicious Filename and File Integrity Monitoring | **Supported.** Every operation on the monitored files produced an event with the resolved  | 1.45+ | yes |
| `QCS-H16-policy-enforcement` | Runtime Policy Enforcement / Process Blocking | **Supported.** The same process rule in audit mode logged the probe execution and let it r | 1.46+ | yes |
| `QCS-H17-deleted-pod-retention` | Deleted Pod Historical Activity and Event Retention | **Supported.** A short-lived container ran a file + process + network sequence, was force- | 1.45+ | yes |
| `QCS-H18-signal-correlation` | Process, File, and Network Event Correlation | **Supported at the sensor level.** The runtime sensor emits every leg of the chain as even | 1.46+ | yes |
| `QCS-H19-sensor-health` | Sensor Coverage and Health Failure Detection | **Supported — the sensor health cycle is real and observable.** A deliberate sensor interr | 1.45+ | yes |

---

## QCS-H01-host-file-access

### QCS-H01 — Container Escape / Host File Access Attempt

**Hypothesis.** When a container reads a file that belongs to the underlying host
(a controlled directory mounted into it), Qualys sees it and can report
**who did it, from where, and what they touched**.

**Verdict.** **Requires RuntimePolicy v2 — not v1.** The hypothesis targets a specific
host file (`…/QCS-H01/canary.txt`), which is expressed with the v2 `Postfix` path
operator. v1 `monitor-paths` are matched as a **Prefix** of the resolved path only —
no Postfix — so v1 cannot determine the host file and this lab is **not covered**
in v1 mode.

**CRS version support: 1.46+** — v2 required (Postfix to scope to the host file)

### RuntimePolicy v1 — not shipped

No `policy-v1.yaml` — v1 has no Postfix and **cannot express this lab**; v1-default
runs auto-fall back to `policy-v2.yaml` (same pattern as QCS-H20).

### RuntimePolicy v2 — `QCS-H01-host-file-access/policy-v2.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h01-host-file-access
spec:
  rules:
  - name: host-path-read
    type: file
    id: host-file-read
    fileOperation: read
    action: audit
    # Postfix exercises the supported operator while staying specific to the
    # marker file: it matches any resolved path ending in the suffix below.
    matchFilePaths:
    - operator: Postfix
      values:
      - /QCS-H01/canary.txt
```

### Workload manifest (pod.yaml) — `QCS-H01-host-file-access/pod.yaml`

```yaml
# QCS-H01 — Container Escape / Host File Access Attempt
# CRS version support: 1.46+ — v2 required (Postfix scopes to the host file;
# v1 monitor-paths are Prefix-only, no Postfix, so v1 cannot cover this lab)
#
# Applying this manifest creates a dedicated namespace, a service account, and
# a pod that mounts the worker node's /var/qualys-poc/QCS-H01 read-only and
# runs ls/stat/cat/sha256sum against the marker file — generating the events
# the RuntimePolicy in policy.yaml should record.
#
# OpenShift: a pod mounting hostPath requires an SCC that allows it (e.g.
# `oc adm policy add-scc-to-user hostmount-anyuid -z citi-h01-sa -n citi-h01`
# or an approved custom SCC). The restricted pod below has no hostPath and
# demonstrates the denied case under restricted-v2.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h01
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: citi-h01-sa
  namespace: citi-h01
---
# Negative case: restricted pod — cannot see the host path at all.
apiVersion: v1
kind: Pod
metadata:
  name: citi-h01-restricted
  namespace: citi-h01
  labels:
    app: citi-h01-restricted
spec:
  serviceAccountName: citi-h01-sa
  restartPolicy: Never
  containers:
  - name: probe
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command: ["sh", "-c", "ls -l /var/qualys-poc/QCS-H01 2>&1; sleep 3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
---
# Test case: elevated pod with the controlled host directory mounted read-only.
apiVersion: v1
kind: Pod
metadata:
  name: citi-h01-elevated
  namespace: citi-h01
  labels:
    app: citi-h01-elevated
spec:
  serviceAccountName: citi-h01-sa
  restartPolicy: Never
  containers:
  - name: probe
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      TARGET=/var/qualys-poc/QCS-H01/canary.txt
      ls -l /var/qualys-poc/QCS-H01
      stat "$TARGET"
      cat "$TARGET"
      sha256sum "$TARGET"
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: host-qualys-poc
      mountPath: /var/qualys-poc/QCS-H01
      readOnly: true
  volumes:
  - name: host-qualys-poc
    hostPath:
      path: /var/qualys-poc/QCS-H01
      type: Directory
```

### Observed data (v2 run)

- `cat` and `sha256sum` — the two commands that actually read the file's
  contents — each produced a detection record containing:
  - the program used (`cat`, `sha256sum`)
  - the exact file path
  - which container it ran in (container id)
  - the full command that launched it, including its parent shell
  - the host (node) it happened on and the exact time
- `ls` and `stat` did not trigger a detection — correct behavior, since
  neither actually reads the file's contents. They still show up in normal
  process activity logs.
- Deleting the test setup does not remove history — the records are
  already captured in the event stream.

### Observed data (v1 run)

`file-read` → `vfs_read` event on the mounted canary (`/usr/bin/cat`, container-attributed)

---

## QCS-H02-runtime-file-drift

### QCS-H02 — Runtime File Drift and Unauthorized Executable Creation

**Hypothesis.** If someone drops a brand-new file or script into a running container —
creates it, changes it, makes it executable, runs it, renames it, deletes
it — Qualys records every step. And in enforcement mode, it can stop the
activity instead of just watching it.

**Verdict.** **It works, in both modes.** Every stage of the file's life produced a
detection record. In enforcement mode, the unauthorized write and the
attempt to run the dropped script were both **killed on the spot** — the
script never ran.

**CRS version support: 1.45+** — v1 file ops + action kill cover drift & enforce; exec-block rule is v2-only (1.46+)

### RuntimePolicy v1 — `QCS-H02-runtime-file-drift/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — one document per base-policy (v1 has no rule list;
# each CR is a single base-policy + monitor set).
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h02-drift-create
spec:
  base-policy: file-create
  action: audit
  monitor-paths:
  - /tmp/citi-h02/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h02-drift-write
spec:
  base-policy: file-write
  action: audit
  monitor-paths:
  - /tmp/citi-h02/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h02-drift-metadata
spec:
  base-policy: file-metadata
  action: audit
  monitor-paths:
  - /tmp/citi-h02/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h02-drift-rename
spec:
  base-policy: file-rename
  action: audit
  monitor-paths:
  - /tmp/citi-h02/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h02-drift-delete
spec:
  base-policy: file-delete
  action: audit
  monitor-paths:
  - /tmp/citi-h02/
```

### RuntimePolicy v2 — `QCS-H02-runtime-file-drift/policy.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h02-file-drift
spec:
  rules:
  - name: drift-create
    type: file
    id: drift-create
    fileOperation: create
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h02/
  - name: drift-write
    type: file
    id: drift-write
    fileOperation: write
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h02/
  - name: drift-metadata
    type: file
    id: drift-metadata
    fileOperation: metadata
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h02/
  - name: drift-rename
    type: file
    id: drift-rename
    fileOperation: rename
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h02/
  - name: drift-delete
    type: file
    id: drift-delete
    fileOperation: delete
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h02/
```

### Workload manifest (pod.yaml) — `QCS-H02-runtime-file-drift/pod.yaml`

```yaml
# QCS-H02 — Runtime File Drift and Unauthorized Executable Creation
# CRS version support: 1.45+ — v1 file ops + action kill cover drift & enforce; exec-block rule is v2-only (1.46+)
#
# Applying this manifest creates a standard non-root pod that drops a new
# script into /tmp after startup, modifies it, makes it executable, runs it,
# then renames and deletes it — the full drift lifecycle that policy.yaml
# (audit) and policy-enforce.yaml (enforcement) should observe.
#
# OpenShift: no special SCC needed — everything happens in the pod's own
# writable /tmp, so the default restricted-v2 profile is enough.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h02
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: citi-h02-sa
  namespace: citi-h02
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h02-drift
  namespace: citi-h02
  labels:
    app: citi-h02-drift
spec:
  serviceAccountName: citi-h02-sa
  restartPolicy: Never
  containers:
  - name: drifter
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      DIR=/tmp/citi-h02
      mkdir -p "$DIR"

      # 1. introduce a new executable after deployment
      printf '#!/bin/sh\necho drift-v1\n' > "$DIR/drift.sh"

      # 2. modify it
      printf '#!/bin/sh\necho drift-v2\n' >> "$DIR/drift.sh"

      # 3. make it executable and run it
      chmod 755 "$DIR/drift.sh"
      stat "$DIR/drift.sh"
      sha256sum "$DIR/drift.sh"
      "$DIR/drift.sh"

      # 4. rename and delete it
      mv "$DIR/drift.sh" "$DIR/drift.sh.renamed"
      rm "$DIR/drift.sh.renamed"

      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v1 run)

All 5 base-policies fired: `security_inode_create`, `vfs_write`, `security_path_chmod`, `security_path_rename`, `security_path_unlink`. Enforce variant `action: kill` → writer SIGKILLed (`rc=137`, `KPROBE_ACTION_SIGKILL`). The v2 "block exec of the dropped script" leg has **no v1 equivalent** (no process-exec base-policy).

---

## QCS-H03-process-lineage

### QCS-H03 — Suspicious Process and Parent-Child Process Detection

**Hypothesis.** When a suspicious command chain runs inside a container — a script that
spawns children, some short-lived, some long-running — Qualys records the
whole family tree: who launched what, what ran, what exited, and what was
killed.

**Verdict.** **Supported, with one honest "partial".** Every launch, every child, every
termination was recorded with the parent, command line, UID and container
attached. The caveat: each record shows the process and its **immediate
parent** — grandparent-and-deeper trees are rebuilt by linking the event
IDs, which the data fully supports but isn't pre-joined in a single event.

**CRS version support: 1.46+** — v2 process rule for the exec flag; v1 file-open is only an approximation

### RuntimePolicy v1 — `QCS-H03-process-lineage/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — v1 has NO process-exec base-policy (security_bprm_check
# is v2-only), so the closest v1 form is file-open on the suspicious script:
# the open fires when the interpreter loads the script — i.e. at launch.
# Lineage itself rides on the base exec/exit stream either way.
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h03-chain-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /tmp/citi-h03-chain.sh
```

### RuntimePolicy v2 — `QCS-H03-process-lineage/policy.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h03-process-lineage
spec:
  rules:
  # Flags the suspicious entry point: any exec of the dropped chain script.
  # Lineage itself is emitted by the base sensor for every process — this
  # rule just marks the exec we care about in the stream.
  - name: chain-exec
    type: process
    id: chain-exec
    action: audit
    matchBinaries:
    - operator: In
      values:
      - /tmp/citi-h03-chain.sh
```

### Workload manifest (pod.yaml) — `QCS-H03-process-lineage/pod.yaml`

```yaml
# QCS-H03 — Suspicious Process and Parent-Child Process Detection
# CRS version support: 1.46+ — v2 process rule for the exec flag; v1 file-open is only an approximation
#
# Applying this manifest creates a pod that runs a controlled process chain:
# shell -> script -> short-lived child (find) + long-running child (sleep)
# -> explicit kill. A unique marker is embedded in the script for event
# correlation. No special SCC needed.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h03
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: citi-h03-sa
  namespace: citi-h03
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h03-chain
  namespace: citi-h03
  labels:
    app: citi-h03-chain
spec:
  serviceAccountName: citi-h03-sa
  restartPolicy: Never
  containers:
  - name: chain
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      MARKER="CITI-H03-$(date +%s)"
      cat > /tmp/citi-h03-chain.sh <<EOF
      #!/bin/sh
      echo "chain-marker $MARKER"
      sleep 300 &
      find /etc -name "*.conf" | head -3
      sleep 2
      kill %1
      EOF
      chmod +x /tmp/citi-h03-chain.sh
      /tmp/citi-h03-chain.sh
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

The complete chain, in order:

```
docker exec → sh (the entry point)
    └─ /tmp/citi-h03-chain.sh        ← flagged by the policy as suspicious
        ├─ sleep 300                  ← long-lived, later killed → exit recorded
        ├─ find /etc -name *.conf     ← short-lived → exit recorded
        ├─ head -3                    ← short-lived → exit recorded
        └─ sleep 2 → kill             ← short-lived → exit recorded
```

Every record carried: binary path, full command line, UID, PID, container
ID, parent binary + parent exec ID, and node name. Launches AND
terminations are both present, including the kill of the long-running
child.

### Observed data (v1 run)

`file-open` on `/tmp/citi-h03-chain.sh` fired at launch (open = the launch marker — v1 has no process-exec base-policy). Lineage still rides on the base exec/exit stream.

---

## QCS-H04-fileless-exec

### QCS-H04 — Fileless or Inline Script Execution

**Hypothesis.** If someone runs a script without ever saving it as a file — typing it into
the shell directly, or piping it in — does Qualys still see what it did?

**Verdict.** **Partially — and the partial part matters.** You can't see the fileless
script *itself*, but you see **everything it does**: every command it
launches, every file it opens, every connection it makes, all attributed
back to the shell that ran it.

**CRS version support: 1.45+** — v1 file-open + net-tcp-open cover inline/activity legs; memfd/fileless rule = future release (raw TP)

### RuntimePolicy v1 — `QCS-H04-fileless-exec/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — canary open + outbound connect, mirroring the v2 pair.
# (v1 monitor-paths are Prefix-matched resolved paths, not filename
# postfixes — hence the full path here.)
# memfd fileless exec has NO v1 base-policy — keep tracingpolicy*.yaml.
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h04-canary-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /etc/citi-h04-canary.txt
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h04-egress-audit
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "80"
  - "443"
  - "8080"
```

### RuntimePolicy v2 — `QCS-H04-fileless-exec/policy.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h04-fileless-exec
spec:
  rules:
  # The fileless script itself leaves no binary on disk — what betrays it is
  # the activity it generates. This rule records every open of the canary.
  - name: canary-open
    type: file
    id: canary-open
    fileOperation: open
    action: audit
    matchFilePaths:
    - operator: Postfix
      values:
      - citi-h04-canary.txt
  # Records the outbound connection the inline script makes.
  - name: egress-audit
    type: network
    id: egress-audit
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "80"
      - "443"
      - "8080"
```

### Workload manifest (pod.yaml) — `QCS-H04-fileless-exec/pod.yaml`

```yaml
# QCS-H04 — Fileless or Inline Script Execution
# CRS version support: 1.45+ — v1 file-open + net-tcp-open cover inline/activity legs; memfd/fileless rule = future release (raw TP)
#
# Applying this manifest creates a pod that:
#   1. drops a canary file,
#   2. runs an inline `sh -c` command touching it,
#   3. feeds a whole script to the interpreter over stdin (nothing stored),
# both generating process, file-open and egress activity for the sensor.
# No special SCC needed.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h04
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h04-fileless
  namespace: citi-h04
  labels:
    app: citi-h04-fileless
spec:
  restartPolicy: Never
  containers:
  - name: workload
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      MARKER="CITI-H04-$(date +%s)"
      echo "$MARKER" > /etc/citi-h04-canary.txt

      # case 1: inline -c — the whole script IS the command line
      sh -c "echo $MARKER-inline; cat /etc/citi-h04-canary.txt; sleep 1"

      # case 2: stdin script — no file, no command-line content
      sh <<'EOF'
      echo "CITI-H04-stdin"
      cat /etc/citi-h04-canary.txt
      sleep 1
      EOF

      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Raw Cilium TracingPolicy fallback — `QCS-H04-fileless-exec/tracingpolicy.yaml`

```yaml
# Raw Cilium TracingPolicy fallback — catches the fileless primitive itself.
# memfd_create is not expressible in RuntimePolicy v2 today (no rule type/
# fileOperation maps to it), so this lab uses the verbatim cilium.io policy.
# Future implementation note: a v2 `fileless`/`memfd` rule type.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: citi-h04-memfd-create
spec:
  kprobes:
  - call: "sys_memfd_create"
    syscall: true
    return: true
    args:
    - index: 0
      type: "string"       # memfd name (attacker-chosen, often innocuous)
    - index: 1
      type: "int"          # MFD_* flags
    returnArg:
      index: 0
      type: "int"          # the anonymous fd
    selectors:
    - matchActions:
      - action: Post
```

### Raw Cilium TracingPolicy fallback — `QCS-H04-fileless-exec/tracingpolicy-block.yaml`

```yaml
# Enforcement fallback — kill any process that calls memfd_create.
# Since matchBinaries cannot resolve a memfd-backed exec to a matchable path
# (verified in RESULT.md), the primitive itself is the enforcement point.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: citi-h04-memfd-create-block
spec:
  kprobes:
  - call: "sys_memfd_create"
    syscall: true
    return: true
    args:
    - index: 0
      type: "string"
    - index: 1
      type: "int"
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchActions:
      - action: Sigkill
```

### Raw Cilium TracingPolicy fallback — `QCS-H04-fileless-exec/policy-memfd-block.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h04-memfd-block
spec:
  rules:
  # Can a process block rule stop a memfd exec? Probe which path form the
  # bprm binary resolves to for a memfd-backed file.
  - name: memfd-block-exec
    type: process
    id: memfd-block-exec
    action: block
    matchBinaries:
    - operator: Prefix
      values:
      - "/proc/self/fd/"
      - "/memfd:"
      - "memfd:"
    - operator: Postfix
      values:
      - "(deleted)"
```

### Observed data (v2 run)

| | Case 1: `sh -c` | Case 2: stdin |
|---|---|---|
| Interpreter seen | Yes — `/bin/sh` | Yes — `/bin/sh` |
| Script content visible | **Yes** — the whole script is in the command line | **No** — launch record shows the shell with *no arguments* |
| Child processes seen | Yes (`cat`, `wget` — with parent = the shell) | Yes (same) |
| File it touched | Canary-open event recorded | Canary-open event recorded |
| Connection it made | Egress event with full address/port/peer | Egress event, same detail |

### Observed data (v1 run)

`file-open` on the canary + `net-tcp-open` on :8080 both fired (`security_file_open`, `tcp_connect`). memfd fileless exec: **no v1 base-policy** — `tracingpolicy*.yaml` raw TPs remain required.

---

## QCS-H05-east-west-visibility

### QCS-H05 — Cross-Namespace East-West Communication Visibility

**Hypothesis.** When a pod in one namespace talks to a service in another namespace, does
Qualys record who talked, to whom, and on what port?

**Verdict.** **It works.** Every connection produced a record with the source program,
source IP, destination IP, port, and protocol — enough to map the
east-west path precisely.

**CRS version support: 1.45+** — v1 net-tcp-open covers it

### RuntimePolicy v1 — `QCS-H05-east-west-visibility/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h05-east-west
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "8080"
```

### RuntimePolicy v2 — `QCS-H05-east-west-visibility/policy.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h05-east-west
spec:
  rules:
  # Records outbound TCP connections to the service port — the east-west
  # path between namespaces. Source process, src/dst IP, port, protocol
  # and connect result are all on the event.
  - name: east-west-egress
    type: network
    id: east-west-egress
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "8080"
```

### Workload manifest (pod.yaml) — `QCS-H05-east-west-visibility/pod.yaml`

```yaml
# QCS-H05 — Cross-Namespace East-West Communication Visibility
# CRS version support: 1.45+ — v1 net-tcp-open covers it
#
# Two namespaces: a client/toolbox pod in citi-h05-client, and an HTTP
# service in citi-h05-target. The client generates requests via both the
# service FQDN and the ClusterIP. The NetworkPolicy allows only this path.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h05-client
---
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h05-target
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h05-httpd
  namespace: citi-h05-target
  labels:
    app: citi-h05-httpd
spec:
  containers:
  - name: httpd
    # OpenShift-native httpd listens on 8080.
    image: registry.access.redhat.com/ubi9/httpd-24:latest
---
apiVersion: v1
kind: Service
metadata:
  name: citi-h05-svc
  namespace: citi-h05-target
spec:
  selector:
    app: citi-h05-httpd
  ports:
  - name: http
    port: 8080
    targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-citi-h05-client
  namespace: citi-h05-target
spec:
  podSelector:
    matchLabels:
      app: citi-h05-httpd
  policyTypes: ["Ingress"]
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: citi-h05-client
    ports:
    - port: 8080
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h05-toolbox
  namespace: citi-h05-client
  labels:
    app: citi-h05-toolbox
spec:
  containers:
  - name: client
    image: registry.access.redhat.com/ubi9/ubi:latest
    command:
    - sh
    - -c
    - |
      SVC=citi-h05-svc.citi-h05-target.svc.cluster.local
      # baseline via service FQDN
      curl -s -o /dev/null "http://$SVC:8080" || true
      # repeated requests via resolved ClusterIP
      IP=$(getent hosts "$SVC" | awk '{print $1}')
      for i in 1 2 3; do curl -s -o /dev/null "http://$IP:8080" || true; sleep 1; done
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

Each request produced a connection record containing:

- **source program** (`wget`) and the container it ran in
- **source IP** of the client (172.19.0.3)
- **destination IP + port** of the service (172.19.0.2:8080)
- **protocol** (TCP) and the connection state at send time
- the **result** of the connect call

Name-based and ClusterIP-based connects are indistinguishable on the wire
— the record always carries the resolved destination address.

### Observed data (v1 run)

`net-tcp-open` :8080 → `tcp_connect` events with src/dst tuple + process attribution

---

## QCS-H06-north-south

### QCS-H06 — Unusual North-South Network Connection

**Hypothesis.** When a container opens an unexpected outbound connection, Qualys detects
it and can say which process made it and where it went — including when
the destination is unreachable.

**Verdict.** **It works.** Successful, refused, and blackholed connections were all
recorded with process + destination attribution. Two honest limits:
visibility is scoped to the ports the policy watches, and UDP DNS lookups
are not part of `tcp_connect` telemetry.

**CRS version support: 1.45+** — v1 net-tcp-open covers TCP; UDP/DNS visibility = future release (raw TP)

### RuntimePolicy v1 — `QCS-H06-north-south/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h06-north-south
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "80"
  - "443"
  - "8080"
```

### RuntimePolicy v2 — `QCS-H06-north-south/policy.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h06-north-south
spec:
  rules:
  # Records outbound TCP connections to the approved web/test ports.
  # Connections to ports NOT listed produce no policy event — visibility
  # is scoped to what the policy watches.
  - name: egress-audit
    type: network
    id: egress-audit
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "80"
      - "443"
      - "8080"
```

### Workload manifest (pod.yaml) — `QCS-H06-north-south/pod.yaml`

```yaml
# QCS-H06 — Unusual North-South Network Connection
# CRS version support: 1.45+ — v1 net-tcp-open covers TCP; UDP/DNS visibility = future release (raw TP)
#
# Pod that performs: DNS resolution then a TCP/HTTP connection to the
# approved destination, a second connection to another approved endpoint,
# and an attempt on a port outside the monitored set for comparison.
# Egress should be restricted to the approved destinations via OpenShift
# egress controls (EgressFirewall/EgressNetworkPolicy) — noted for the
# field deployment.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h06
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h06-client
  namespace: citi-h06
  labels:
    app: citi-h06-client
spec:
  restartPolicy: Never
  containers:
  - name: client
    image: registry.access.redhat.com/ubi9/ubi:latest
    command:
    - sh
    - -c
    - |
      APPROVED=approved-http.citi-h06-target.svc.cluster.local
      # DNS resolution followed by the connection
      getent hosts "$APPROVED"
      curl -s -o /dev/null "http://$APPROVED/" || true
      # second approved test destination
      curl -s -o /dev/null "http://$APPROVED:8080/" || true
      # attempt on a port outside the approved/monitored set
      curl -s --connect-timeout 2 -o /dev/null "http://$APPROVED:9090/" || true
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Raw Cilium TracingPolicy fallback — `QCS-H06-north-south/tracingpolicy-dns.yaml`

```yaml
# OPTIONAL raw fallback — DNS lookups are UDP, which tcp_connect never sees.
# This cilium.io policy audits outbound UDP+TCP datagrams to port 53 on the
# ip_output hook (same approach as examples/tracingpolicy/dns-only-*.yaml),
# so the DNS leg of a north-south connection is also recorded.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: citi-h06-dns-audit
spec:
  kprobes:
  - call: "ip_output"
    syscall: false
    args:
    - index: 2
      type: "skb"
    selectors:
    - matchArgs:
      - index: 2
        operator: "DPort"
        values:
        - "53"
      - index: 2
        operator: "Protocol"
        values:
        - "IPPROTO_UDP"
      matchActions:
      - action: Post
```

### Observed data (v2 run)

| Attempt | Recorded? |
|---|---|
| Connect to approved port 8080 (success) | Yes — full 5-tuple + process |
| Connect to port 443 — **connection refused** | Yes — identical record shape |
| Connect to unreachable IP (times out) | Yes — identical record shape |
| Connect to port 9090 — **not in the policy list** | No — policy-scoped visibility |
| DNS lookup (`getent`, UDP to resolver) | Not via tcp_connect — see below |

### Observed data (v1 run)

`net-tcp-open` 80/443/8080 → allowed, refused, and blackholed connects all recorded; unlisted :9090 silent. DNS/UDP still raw-TP only.

---

## QCS-H07-netpol-denied

### QCS-H07 — Network Policy Violation and Denied Connection Attempt

**Hypothesis.** When the platform (NetworkPolicy / firewall) blocks a connection, does
Qualys still record the attempt — or only successful connections?

**Verdict.** **The attempt is recorded, always.** Qualys sees the connection the
moment it is initiated — before the platform drops it — so denied flows
produce the same event as allowed ones. Whether it succeeded must be
corroborated with platform evidence, not from the event alone.

**CRS version support: 1.45+** — v1 net-tcp-open covers it

### RuntimePolicy v1 — `QCS-H07-netpol-denied/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h07-netpol-denied
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "8080"
```

### RuntimePolicy v2 — `QCS-H07-netpol-denied/policy.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h07-netpol-denied
spec:
  rules:
  # Audit every outbound TCP connect to the service port — the question is
  # whether the ATTEMPT is recorded when the platform denies the flow.
  - name: egress-audit
    type: network
    id: egress-audit
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "8080"
```

### Workload manifest (pod.yaml) — `QCS-H07-netpol-denied/pod.yaml`

```yaml
# QCS-H07 — Network Policy Violation and Denied Connection Attempt
# CRS version support: 1.45+ — v1 net-tcp-open covers it
#
# Two namespaces, a service in the target, and two NetworkPolicy manifests:
# apply `allow-citi-h07-client` for the baseline, then delete it and apply
# `default-deny-citi-h07` and repeat the same curl — comparing telemetry
# for allowed vs denied flows.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h07-client
---
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h07-target
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h07-httpd
  namespace: citi-h07-target
  labels:
    app: citi-h07-httpd
spec:
  containers:
  - name: httpd
    image: registry.access.redhat.com/ubi9/httpd-24:latest
---
apiVersion: v1
kind: Service
metadata:
  name: citi-h07-svc
  namespace: citi-h07-target
spec:
  selector:
    app: citi-h07-httpd
  ports:
  - port: 8080
    targetPort: 8080
---
# BASELINE — apply this first, verify connects succeed.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-citi-h07-client
  namespace: citi-h07-target
spec:
  podSelector:
    matchLabels:
      app: citi-h07-httpd
  policyTypes: ["Ingress"]
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: citi-h07-client
    ports:
    - port: 8080
---
# DENY CASE — swap to this for the violation attempt.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-citi-h07
  namespace: citi-h07-target
spec:
  podSelector:
    matchLabels:
      app: citi-h07-httpd
  policyTypes: ["Ingress"]
  ingress: []
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h07-toolbox
  namespace: citi-h07-client
  labels:
    app: citi-h07-toolbox
spec:
  containers:
  - name: client
    image: registry.access.redhat.com/ubi9/ubi:latest
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

| Attempt | Outcome | Event recorded? |
|---|---|---|
| Baseline connect | Succeeded | Yes — src/dst/port/process |
| Same connect under the DROP rule | **Timed out — denied** | **Yes — identical record** |

Both events are byte-for-byte the same shape: the attempt lands in the
stream at SYN-send; the refusal/drop happens afterwards and does not
erase it.

### Observed data (v1 run)

`net-tcp-open` :8080 → denied/blackholed attempt recorded identically to successes (attempt, not outcome)

---

## QCS-H08-data-exfil

### QCS-H08 — Controlled Data Transfer / Exfiltration Simulation

**Hypothesis.** When a process reads a file and sends it out of the container, can Qualys
tie the read and the send to the same actor — including when the work is
done by a script created at runtime?

**Verdict.** **It works — the correlation is exact.** The file-open event and the
outbound-connection event carry the same process PID and the same parent
chain, so "this process read this file and connected to that endpoint" is
a single joined story, not two guesses.

**CRS version support: 1.45+** — v1 file-open + net-tcp-open cover it

### RuntimePolicy v1 — `QCS-H08-data-exfil/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h08-payload-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /tmp/citi-h08-payload.txt
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h08-egress-audit
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "8080"
```

### RuntimePolicy v2 — `QCS-H08-data-exfil/policy.yaml`

```yaml
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h08-data-exfil
spec:
  rules:
  # Records every open of the synthetic data file — the "read" leg.
  - name: payload-open
    type: file
    id: payload-open
    fileOperation: open
    action: audit
    matchFilePaths:
    - operator: Postfix
      values:
      - citi-h08-payload.txt
  # Records the outbound connection carrying the upload — the "send" leg.
  - name: egress-audit
    type: network
    id: egress-audit
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "8080"
```

### Workload manifest (pod.yaml) — `QCS-H08-data-exfil/pod.yaml`

```yaml
# QCS-H08 — Controlled Data Transfer / Exfiltration Simulation
# CRS version support: 1.45+ — v1 file-open + net-tcp-open cover it
#
# Pod carrying a synthetic payload file that reads it and uploads it to the
# approved internal receiver, then repeats via a script created at runtime.
# Egress should be restricted to the receiver via OpenShift egress controls.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h08
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h08-source
  namespace: citi-h08
  labels:
    app: citi-h08-source
spec:
  restartPolicy: Never
  containers:
  - name: source
    image: registry.access.redhat.com/ubi9/ubi:latest
    command:
    - sh
    - -c
    - |
      MARKER="CITI-H08-$(date +%s)"
      DEST=http://citi-h08-receiver.citi-h08-recv.svc.cluster.local:8080
      echo "synthetic-payload $MARKER" > /tmp/citi-h08-payload.txt

      # direct upload
      curl -s --upload-file /tmp/citi-h08-payload.txt "$DEST/upload1" || true

      # same transfer performed by a runtime-created script
      cat > /tmp/citi-h08-upload.sh <<EOF
      #!/bin/sh
      curl -s --upload-file /tmp/citi-h08-payload.txt "$DEST/upload2" || true
      EOF
      chmod +x /tmp/citi-h08-upload.sh
      /tmp/citi-h08-upload.sh

      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

Upload 1 (direct `wget`):

```
wget (pid N)  → opened /tmp/citi-h08-payload.txt   [payload-open rule]
wget (pid N)  → connected 172.19.0.2:8080          [egress-audit rule]
parent: /bin/sh
```

Upload 2 (runtime script):

```
/bin/sh → /tmp/citi-h08-upload.sh → wget (pid M)
                                    → opened the payload file
                                    → connected to the receiver
```

Same file, same destination, same process on both legs — and the second
run additionally proves the transfer is attributed **through the
just-created script** as the parent.

### Observed data (v1 run)

`file-open` on payload + `net-tcp-open` :8080 → open + connect events on the same chain

---

## QCS-H09-service-account-token

### QCS-H09 — Service Account Token Access and Kubernetes API Activity

**Hypothesis.** When a workload reads its mounted service-account token and then talks to
the Kubernetes API, does Qualys record the token access, the process that
did it, the API connection, and which workload it was?

**Verdict.** **Supported.** The token-file opens and the API connection were both
recorded, each carrying the executing binary, its parent, and the
container identity. What Qualys does **not** see is *what the API call
was* or *whether it was allowed* — that lives inside TLS and only exists
in the cluster's API audit log.

**CRS version support: 1.45+** — v1 file-open + net-tcp-open cover it

### RuntimePolicy v1 — `QCS-H09-service-account-token/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — token open + API egress.
# monitor-paths are Prefix-matched on the RESOLVED path: /var/run is a
# symlink to /run, so the /run prefix is the one that fires (see H09 v2).
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h09-sa-token-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /run/secrets/kubernetes.io/serviceaccount/
  - /var/run/secrets/kubernetes.io/serviceaccount/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h09-k8s-api-egress
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "443"
  - "6443"
```

### RuntimePolicy v2 — `QCS-H09-service-account-token/policy.yaml`

```yaml
# RuntimePolicy v2 — auto-translated by `ebpf-operator tracingpolicy add` into
# per-rule Cilium TracingPolicies named citi-h09-sa-token-v2-<rule-id>.
#
# Watches the two Qualys-visible halves of the hypothesis:
#   sa-token-read  — opens of anything under the service-account mount
#   k8s-api-egress — outbound connects to the standard API ports
# The API request itself (resource, namespace, allow/deny) rides inside
# TLS — that part only exists in the cluster's audit log, not in events.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h09-sa-token
spec:
  rules:
  - name: sa-token-read
    type: file
    id: sa-token-read
    fileOperation: open
    action: audit
    # /var/run is a symlink to /run on essentially every modern image —
    # matchFilePaths sees the RESOLVED path, so the /run prefix is the one
    # that actually fires (verified). Both are listed for runtimes/images
    # where /var/run is a real directory.
    matchFilePaths:
    - operator: Prefix
      values:
      - /run/secrets/kubernetes.io/serviceaccount/
      - /var/run/secrets/kubernetes.io/serviceaccount/
  - name: k8s-api-egress
    type: network
    id: k8s-api-egress
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "443"
      - "6443"
```

### Workload manifest (pod.yaml) — `QCS-H09-service-account-token/pod.yaml`

```yaml
# QCS-H09 — Service Account Token Access and Kubernetes API Activity
# CRS version support: 1.45+ — v1 file-open + net-tcp-open cover it
#
# Creates: a dedicated namespace, a read-only service account with token
# automount explicitly enabled, a second namespace the SA cannot see, and a
# pod that (1) reads the mounted token/namespace files then (2) queries the
# API for an approved resource in its own namespace and (3) attempts the
# same query in the other namespace (expected: 403 Forbidden).
#
# OpenShift: no special SCC needed — the pod is fully restricted.
# Corroborate with API audit logs (the 403 only exists there, not in any
# Qualys event — TLS hides the request itself).
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h09
---
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h09-other
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: citi-h09-sa
  namespace: citi-h09
automountServiceAccountToken: true
---
# Minimal read-only RBAC: get/list/watch ConfigMaps in citi-h09 ONLY.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: citi-h09-read-cm
  namespace: citi-h09
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: citi-h09-read-cm
  namespace: citi-h09
subjects:
- kind: ServiceAccount
  name: citi-h09-sa
  namespace: citi-h09
roleRef:
  kind: Role
  name: citi-h09-read-cm
  apiGroup: rbac.authorization.k8s.io
---
# Approved, non-sensitive resource the SA is allowed to read.
apiVersion: v1
kind: ConfigMap
metadata:
  name: citi-h09-approved
  namespace: citi-h09
data:
  note: "harmless approved resource for QCS-H09"
---
# Non-sensitive resource in a namespace the SA has NO rights to.
apiVersion: v1
kind: ConfigMap
metadata:
  name: citi-h09-off-limits
  namespace: citi-h09-other
data:
  note: "harmless but unauthorized for citi-h09-sa (expect 403)"
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h09-workload
  namespace: citi-h09
spec:
  serviceAccountName: citi-h09-sa
  automountServiceAccountToken: true
  restartPolicy: Never
  containers:
  - name: workload
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - |
      SADIR=/var/run/secrets/kubernetes.io/serviceaccount
      API=https://kubernetes.default.svc:443
      echo "== 1. read mounted SA token material =="
      ls -l "$SADIR"
      cat "$SADIR/namespace"
      wc -c < "$SADIR/token"
      echo "== 2. authorized query (own namespace) =="
      curl -sS --cacert "$SADIR/ca.crt" \
        -H "Authorization: Bearer $(cat $SADIR/token)" \
        "$API/api/v1/namespaces/citi-h09/configmaps" | head -20
      echo "== 3. unauthorized query (other namespace) =="
      curl -sS --cacert "$SADIR/ca.crt" \
        -H "Authorization: Bearer $(cat $SADIR/token)" \
        "$API/api/v1/namespaces/citi-h09-other/configmaps"
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

| Hypothesis asks for | Status |
|---|---|
| Token-file access recorded | Yes — `security_file_open` event per file opened (`namespace`, `token`) |
| Executing process on the access | Yes — `binary` (`cat`) + parent (`bash`) on every event |
| API network connection | Yes — `tcp_connect` egress with full tuple (dst 172.17.0.1:6443) |
| Workload identity | Container ID on every event; pod/namespace fields populate under k8s/OpenShift only |
| Which API resource / which namespace was queried | **No** — request body is inside TLS |
| Whether the API allowed it | **No** — the connect event fires at SYN-send; the 200/403 is an HTTP-layer fact only the API audit log has |

### Observed data (v1 run)

`file-open` on `/run/secrets/…` (resolved path — `/var/run` is a symlink) + `net-tcp-open` 443/6443 → token opens (`cat` ← `bash`) + API connects recorded

---

## QCS-H10-cross-ns-rbac

### QCS-H10 — Cross-Namespace RBAC Access Attempt

**Hypothesis.** When a workload queries the Kubernetes API in a namespace it's allowed to
see and then in one it's *not*, does Qualys capture the API connection and
the initiating process — for both the authorized and the denied call?

**Verdict.** **Supported for visibility; the allow/deny verdict is not Qualys's job.**
Every API-bound connection was recorded with the initiating binary,
parent, and container identity — authorized and unauthorized calls are
**byte-for-byte identical events**. Which call was denied (HTTP 403)
exists only in the Kubernetes/OpenShift API audit log.

**CRS version support: 1.45+** — v1 file-open + net-tcp-open cover it

### RuntimePolicy v1 — `QCS-H10-cross-ns-rbac/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h10-sa-token-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /run/secrets/kubernetes.io/serviceaccount/
  - /var/run/secrets/kubernetes.io/serviceaccount/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h10-k8s-api-egress
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "443"
  - "6443"
```

### RuntimePolicy v2 — `QCS-H10-cross-ns-rbac/policy.yaml`

```yaml
# RuntimePolicy v2 — auto-translated by `ebpf-operator tracingpolicy add` into
# per-rule Cilium TracingPolicies named citi-h10-cross-ns-v2-<rule-id>.
#
# Same two Qualys-visible surfaces as H09, here framing authorized vs
# unauthorized API operations: the token file open tells you WHICH
# workload identity is in play, the egress connect tells you the workload
# talked to the API. Whether the API allowed the operation is only in
# the cluster audit log — both allowed and denied calls look identical
# on the wire (see RESULT.md / QCS-H06, H07).
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h10-cross-ns
spec:
  rules:
  - name: sa-token-read
    type: file
    id: sa-token-read
    fileOperation: open
    action: audit
    # matchFilePaths sees the RESOLVED path — /var/run is a symlink to
    # /run, so the /run prefix is the one that fires (see QCS-H09).
    matchFilePaths:
    - operator: Prefix
      values:
      - /run/secrets/kubernetes.io/serviceaccount/
      - /var/run/secrets/kubernetes.io/serviceaccount/
  - name: k8s-api-egress
    type: network
    id: k8s-api-egress
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "443"
      - "6443"
```

### Workload manifest (pod.yaml) — `QCS-H10-cross-ns-rbac/pod.yaml`

```yaml
# QCS-H10 — Cross-Namespace RBAC Access Attempt
# CRS version support: 1.45+ — v1 file-open + net-tcp-open cover it
#
# Source namespace (citi-h10-src) holds the service account + a Role that
# can only read ConfigMaps there. Target namespace (citi-h10-dst) holds a
# harmless ConfigMap the SA cannot touch. The pod runs an authorized query
# in the source namespace, then the same class of query against the target
# namespace (expected: 403 Forbidden).
#
# Qualys-side evidence: token file open + API egress connects + initiating
# process. Authorization result: OpenShift/K8s audit logs only.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h10-src
---
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h10-dst
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: citi-h10-sa
  namespace: citi-h10-src
automountServiceAccountToken: true
---
# RBAC confined to the source namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: citi-h10-src-read-cm
  namespace: citi-h10-src
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: citi-h10-src-read-cm
  namespace: citi-h10-src
subjects:
- kind: ServiceAccount
  name: citi-h10-sa
  namespace: citi-h10-src
roleRef:
  kind: Role
  name: citi-h10-src-read-cm
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: citi-h10-allowed
  namespace: citi-h10-src
data:
  note: "harmless resource citi-h10-sa MAY read"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: citi-h10-denied
  namespace: citi-h10-dst
data:
  note: "harmless but out of scope for citi-h10-sa (expect 403)"
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h10-workload
  namespace: citi-h10-src
spec:
  serviceAccountName: citi-h10-sa
  automountServiceAccountToken: true
  restartPolicy: Never
  containers:
  - name: workload
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - |
      SADIR=/var/run/secrets/kubernetes.io/serviceaccount
      API=https://kubernetes.default.svc:443
      TOKEN=$(cat "$SADIR/token")
      echo "== allowed: list configmaps in citi-h10-src =="
      curl -sS -w "HTTP %{http_code}\n" --cacert "$SADIR/ca.crt" \
        -H "Authorization: Bearer $TOKEN" \
        "$API/api/v1/namespaces/citi-h10-src/configmaps" -o /tmp/src.json
      echo "== allowed: get citi-h10-allowed in citi-h10-src =="
      curl -sS -w "HTTP %{http_code}\n" --cacert "$SADIR/ca.crt" \
        -H "Authorization: Bearer $TOKEN" \
        "$API/api/v1/namespaces/citi-h10-src/configmaps/citi-h10-allowed" -o /tmp/cm.json
      echo "== denied: list configmaps in citi-h10-dst =="
      curl -sS -w "HTTP %{http_code}\n" --cacert "$SADIR/ca.crt" \
        -H "Authorization: Bearer $TOKEN" \
        "$API/api/v1/namespaces/citi-h10-dst/configmaps"
      echo "== denied: get citi-h10-denied in citi-h10-dst =="
      curl -sS -w "HTTP %{http_code}\n" --cacert "$SADIR/ca.crt" \
        -H "Authorization: Bearer $TOKEN" \
        "$API/api/v1/namespaces/citi-h10-dst/configmaps/citi-h10-denied"
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

| Operation | Event recorded | What it shows |
|---|---|---|
| Client reads SA token | `security_file_open` on `…/serviceaccount/token` | `cat` under `bash`, container ID |
| Authorized query (src ns) | `tcp_connect` → :6443 `TCP_SYN_SENT` | `bash`, dst tuple, container ID |
| **Denied** query (dst ns) | `tcp_connect` → :6443 `TCP_SYN_SENT` | **identical** to the authorized event |
| Unreachable API (:443 refused) | `tcp_connect` → :443 `TCP_SYN_SENT` | also identical — attempt, not outcome |

The two lessons from earlier labs stack here:

- `tcp_connect` fires at SYN-send — success, refusal, and later-403 all
  look the same on the event (H06/H07).
- API requests and responses ride inside TLS — the URI (`/namespaces/dst/…`)
  and the `403 Forbidden` never appear in any event.

### Observed data (v1 run)

Same v1 pair → authorized, denied, and refused connects all recorded as identical `tcp_connect`/`TCP_SYN_SENT` events

---

## QCS-H11-priv-escalation

### QCS-H11 — Privilege Escalation Configuration Detection

**Hypothesis.** When a workload runs with elevated privileges (extra capabilities, root,
setuid binaries), does Qualys flag the elevated runtime context — and can
it tell an elevated exec from a normal one?

**Verdict.** **Supported for runtime context; the pod-spec admission verdict is a
separate concern.** With `--enable-process-cred`, every exec event carries
the process's capability sets (`process.cap.permitted/effective`) and
`binary_properties` (setuid/setgid/file-caps). A raw TracingPolicy
capability-change hook fired **exactly once — on the container granted
CAP_SYS_ADMIN, and never on the normal control**.

**CRS version support: 1.46+** — v2 exec events carry cap context; cap-change rule = future release (raw TP)

### RuntimePolicy v1 — `QCS-H11-priv-escalation/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — no capability/privilege base-policy exists (v1 is
# file/network only). Closest form: file-read/open on the probe binary
# when it is executed (the interpreter reads it at exec). The elevated
# context itself is not expressible in v1.
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h11-probe-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /usr/bin/id
```

### RuntimePolicy v2 — `QCS-H11-priv-escalation/policy.yaml`

```yaml
# QCS-H11 — Privilege Escalation Configuration Detection
#
# v2 has no capability/privilege rule type, so the detection rides on the
# exec sensor: with --enable-process-cred the process_exec event carries
# binary_properties (setuid/setgid/caps). That flags elevated EXECUTION,
# not the pod spec itself. The pod spec admission verdict is an
# OpenShift/Qualys-configuration concern, not a runtime event.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h11-priv-escalation
spec:
  rules:
  # Flags execs of the probe binary; the elevated context is read from the
  # event's process.cap / binary_properties fields (setuid bit, permitted
  # caps), which are only populated when the agent runs with
  # --enable-process-cred.
  - name: elevated-exec
    type: process
    id: elevated-exec
    action: audit
    matchBinaries:
    - operator: In
      values:
      - /usr/bin/id
      - /usr/bin/env
```

### Workload manifest (pod.yaml) — `QCS-H11-priv-escalation/pod.yaml`

```yaml
# QCS-H11 — Privilege Escalation Configuration Detection
# CRS version support: 1.46+ — v2 exec events carry cap context; cap-change rule = future release (raw TP)
#
# One manifest per risky setting, applied SEPARATELY so admission and
# runtime evidence stay attributable. All pods non-root-hostile EXCEPT the
# tested dimension. The "elevated" pod below is the privileged dimension
# (SCC would need to allow it on OpenShift).
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h11
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: citi-h11-sa
  namespace: citi-h11
---
# Baseline — fully restricted pod (control).
apiVersion: v1
kind: Pod
metadata:
  name: citi-h11-restricted
  namespace: citi-h11
spec:
  serviceAccountName: citi-h11-sa
  restartPolicy: Never
  containers:
  - name: probe
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command: ["sh", "-c", "id; sleep 3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
---
# Elevated — adds CAP_SYS_ADMIN and runs as root (the risky dimension).
# OpenShift: requires an approved custom SCC (e.g. anyuid + SYS_ADMIN).
apiVersion: v1
kind: Pod
metadata:
  name: citi-h11-elevated
  namespace: citi-h11
spec:
  serviceAccountName: citi-h11-sa
  restartPolicy: Never
  containers:
  - name: probe
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      id
      capsh --print 2>/dev/null || cat /proc/self/status | grep Cap
      sleep 3600
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: true
      capabilities:
        add: ["SYS_ADMIN"]
```

### Raw Cilium TracingPolicy fallback — `QCS-H11-priv-escalation/tracingpolicy.yaml`

```yaml
# Raw Cilium TracingPolicy — capability-change detection, which RuntimePolicy
# v2 cannot express (no cap rule type). Hooks security_bprm_check and fires
# only when the exec'd process gains the CAP_SYS_ADMIN effective capability.
# Future implementation: a v2 `matchCapabilities` rule field.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: citi-h11-cap-change
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    return: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchCapabilityChanges:
      - type: Effective
        operator: In
        isNamespaceCapability: false
        values:
        - CAP_SYS_ADMIN
      matchActions:
      - action: Post
```

### Observed data (v2 run)

| | Elevated (A) | Normal (B) |
|---|---|---|
| `process.cap.permitted` contains CAP_SYS_ADMIN | **yes** | no |
| v2 exec-flag event (probe binary) | yes | yes (it watches the binary, not the privilege) |
| cap-change event (`matchCapabilityChanges`) | **1 event** | **0 events** |

- The exec events carry container id (`docker`), binary, argv; pod/namespace
  fields populate under k8s/OpenShift.
- The cap-change raw policy fired once for the privileged container and
  zero times for the control — a clean positive/negative pair.

### Observed data (v1 run)

Converted + load-verified (`v1convert` → `ebpf-operator add`). No capability base-policy in v1 — `file-open` on the probe binary is the closest form.

---

## QCS-H12-vuln-image-in-use

### QCS-H12 — Vulnerable Image Discovery and "In Use" Prioritization

**Hypothesis.** Qualys finds a vulnerability in a deployed image — and can tell whether
the vulnerable package is *actually used* at runtime (invoked) or merely
*present* in the image.

**Verdict.** **Partial — and the split is clean.** The registry side (vuln discovery,
CVSS, fix versions, "in use" UI) is a Qualys *image-scanning* capability,
not a runtime event — out of scope for the runtime sensor. The **runtime
"in use" half is proven**: a policy on the vulnerable binary fired for the
workload that invoked it and produced **zero events** for the workload
that never ran it.

**CRS version support: 1.46+** — v2 process rule needed (no v1 process-exec)

### RuntimePolicy v1 — `QCS-H12-vuln-image-in-use/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — no process-exec base-policy; closest is file-open on
# the vulnerable binary (fires when it is loaded for execution).
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h12-vuln-pkg-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /usr/bin/bash
```

### RuntimePolicy v2 — `QCS-H12-vuln-image-in-use/policy.yaml`

```yaml
# QCS-H12 — Vulnerable Image "In Use" Prioritization
#
# The REGISTRY-SCAN leg (vuln discovery, CVSS, fix versions) is a Qualys
# platform capability — not a eBPF-Agent runtime event. What the runtime
# sensor CAN prove is the "in use" half: which workload actually EXECUTED
# the vulnerable binary. This policy flags exec of the target package, so
# image A (invokes it) generates events and image B (package present, not
# invoked) generates none — the runtime side of in-use prioritization.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h12-vuln-pkg-exec
spec:
  rules:
  - name: vuln-pkg-exec
    type: process
    id: vuln-pkg-exec
    action: audit
    matchBinaries:
    - operator: In
      values:
      - /usr/bin/bash
```

### Workload manifest (pod.yaml) — `QCS-H12-vuln-image-in-use/pod.yaml`

```yaml
# QCS-H12 — Vulnerable Image "In Use" Prioritization
# CRS version support: 1.46+ — v2 process rule needed (no v1 process-exec)
#
# Two workloads from images that BOTH carry the target package (here
# openssl): the "used" pod invokes it, the "unused" pod never runs it.
# Image scan results (vuln + CVSS) come from the registry scan, not from
# these manifests.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h12
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h12-used
  namespace: citi-h12
spec:
  restartPolicy: Never
  containers:
  - name: used
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      bash -c "echo in-use-marker"  # invoke the vulnerable package
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h12-unused
  namespace: citi-h12
spec:
  restartPolicy: Never
  containers:
  - name: unused
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      echo "package present, never invoked"
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

- **A**: 1 policy event (`security_bprm_check`, arg `linux_binprm_arg.path=/usr/bin/bash`) + the paired `process_exec` with container id `34805c32…`, argv `-c "echo in-use-marker"`.
- **B**: **0 policy events** — the package sits in the image but produces no runtime signal.
- Join for the full picture: policy event (which binary matched) + exec event (which container) + image-scan result (which CVE).

### Observed data (v1 run)

Converted + load-verified. v1 has no process-exec base-policy — `file-open` on the package binary approximates the in-use signal.

---

## QCS-H13-image-lineage-drift

### QCS-H13 — Image Lineage and Runtime Integrity Change

**Hypothesis.** Qualys preserves image lineage (digest, layers, build history) and can
tell immutable image content apart from changes made at runtime.

**Verdict.** **Partial — image lineage is platform data, runtime drift is sensor
data.** The runtime side is fully proven: every post-deploy create/write/
open under the monitored directory is recorded with path, process,
container id, and timestamp. What the sensor cannot see is the *image*
itself — digests, layer diffs, and "which layer this file came from" are
Qualys platform/registry data. The join is: FIM events (drift) vs scan
layers (baseline) — anything FIM sees that no layer contains is runtime
drift *by definition*.

**CRS version support: 1.45+** — v1 file-create/write/open cover drift

### RuntimePolicy v1 — `QCS-H13-image-lineage-drift/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h13-drift-create
spec:
  base-policy: file-create
  action: audit
  monitor-paths:
  - /var/qualys-citi/h13/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h13-drift-write
spec:
  base-policy: file-write
  action: audit
  monitor-paths:
  - /var/qualys-citi/h13/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h13-drift-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /var/qualys-citi/h13/
```

### RuntimePolicy v2 — `QCS-H13-image-lineage-drift/policy.yaml`

```yaml
# QCS-H13 — Image Lineage vs Runtime Integrity Change
#
# IMAGE side (digest, layers, build history, diff between v1 and v2) is a
# Qualys platform/registry capability — eBPF-Agent events carry no layer
# data. RUNTIME side: this FIM rule records every create/write under the
# writable dir after deployment, i.e. drift that is BY DEFINITION not part
# of the image. Joining the two (which events have no matching layer) is
# the platform's job; the sensor provides the drift evidence.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h13-drift
spec:
  rules:
  - name: drift-create
    type: file
    id: drift-create
    fileOperation: create
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /var/qualys-citi/h13/
  - name: drift-write
    type: file
    id: drift-write
    fileOperation: write
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /var/qualys-citi/h13/
  - name: drift-open
    type: file
    id: drift-open
    fileOperation: open
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /var/qualys-citi/h13/
```

### Workload manifest (pod.yaml) — `QCS-H13-image-lineage-drift/pod.yaml`

```yaml
# QCS-H13 — Image Lineage vs Runtime Integrity Change
# CRS version support: 1.45+ — v1 file-create/write/open cover drift
#
# Pod image version 1. A companion pod mounts version 2 (same tag updated,
# different digest). After deploy, a runtime change is introduced under
# /var/qualys-citi/h13 — the sensor should flag it as drift (it is not in
# any image layer).
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h13
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h13-v1
  namespace: citi-h13
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      mkdir -p /var/qualys-citi/h13
      # image-baked content (part of the image; NOT drift)
      echo "baked-v1" > /var/qualys-citi/h13/baked.txt
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h13-v2
  namespace: citi-h13
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      mkdir -p /var/qualys-citi/h13
      echo "baked-v2" > /var/qualys-citi/h13/baked.txt
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

All three operations fired with full attribution (container `6fb65041…`):

- `security_inode_create` — dir/files created (`bash`)
- `vfs_write` — both files written (`bash`)
- `security_file_open` — opens incl. the read-back by `cat`

### Observed data (v1 run)

Converted + load-verified (3 base-policies: create/write/open).

---

## QCS-H14-file-hash

### QCS-H14 — Malicious or Test File Hash Detection

**Hypothesis.** Qualys can find a file by its known MD5/SHA-256 hash in an image and/or a
running container.

**Verdict.** **Not supported by the runtime sensor.** Verified two ways: (1) by
inspection — no hash operator exists in RuntimePolicy v2 filters
(`matchFilePaths`/`matchBinaries`/`matchArguments` are path/binary/arg
string compares) nor in raw Cilium TracingPolicy arg operators; exec/file
events carry **no file-hash fields**; (2) live — the marker file with a
known sha256 produced path-based events only. Hash search (image scan +
inventory) is a Qualys *platform* feature, not a runtime event.

**CRS version support: 1.45+** — path-only detection (v1); hash detection not supported at runtime (platform)

### RuntimePolicy v1 — `QCS-H14-file-hash/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h14-marker-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /tmp/citi-h14-marker.txt
```

### RuntimePolicy v2 — `QCS-H14-file-hash/policy.yaml`

```yaml
# QCS-H14 — Malicious/Test File Hash Detection
#
# HYPOTHESIS IS NOT SUPPORTED: no hash-based matching exists anywhere in
# the runtime sensor. Verified by inspection: RuntimePolicy v2 filters are
# matchFilePaths/matchBinaries/matchArguments (paths/binary names/args —
# never hashes); raw Cilium TracingPolicy arg operators are string
# compares only. process_exec events carry no file-hash fields either.
#
# This policy is what IS possible: detect the file by PATH and record its
# opens/creates. Hash search ("find this hash in images/containers") is a
# Qualys image-scanning platform feature, not a runtime event.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h14-marker-file
spec:
  rules:
  - name: marker-open
    type: file
    id: marker-open
    fileOperation: open
    action: audit
    matchFilePaths:
    - operator: Postfix
      values:
      - citi-h14-marker.txt
  - name: marker-create
    type: file
    id: marker-create
    fileOperation: create
    action: audit
    matchFilePaths:
    - operator: Postfix
      values:
      - citi-h14-marker.txt
```

### Workload manifest (pod.yaml) — `QCS-H14-file-hash/pod.yaml`

```yaml
# QCS-H14 — Malicious/Test File Hash Detection
# CRS version support: 1.45+ — path-only detection (v1); hash detection not supported at runtime (platform)
#
# Image layer: the marker file ships INSIDE the image (baked), so it has a
# precomputed hash at scan time. Runtime layer: the same content is copied
# into the writable path after deploy. The scan-side hash lookup is a
# Qualys platform feature; the runtime side can only see the file by PATH.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h14
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h14-workload
  namespace: citi-h14
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      # image-baked marker (same bytes as the scanned artifact)
      printf 'EICAR-SIMULATION citi-h14-marker\n' > /etc/citi-h14-marker.txt
      sha256sum /etc/citi-h14-marker.txt
      # runtime copy of the same bytes into the writable path
      mkdir -p /tmp
      cp /etc/citi-h14-marker.txt /tmp/citi-h14-marker.txt
      sha256sum /tmp/citi-h14-marker.txt
      cat /tmp/citi-h14-marker.txt
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

- Both copies produced `security_file_open` events with the **path**
  (`/etc/citi-h14-marker.txt`, `/tmp/citi-h14-marker.txt`) and process
  attribution — but no hash anywhere in the event args.
- No policy construct can express "match this sha256". The events record
  *what was opened*, never *what the bytes were*.

### Observed data (v1 run)

Converted + load-verified — path-only detection confirmed; no hash support in v1 either.

---

## QCS-H15-suspicious-filename

### QCS-H15 — Suspicious Filename and File Integrity Monitoring

**Hypothesis.** Qualys can watch selected filenames in a running container and record the
full lifecycle: create, modify, rename, read, delete — including
re-creation by a child process — with the filename, operation, process,
parent, and workload attached.

**Verdict.** **Supported.** Every operation on the monitored files produced an event
with the resolved path, operation, binary, parent, and container id.
Recreation through a child `sh` was attributed to the child with the
parent shell on the event.

**CRS version support: 1.45+** — v1 file base-policies cover full FIM

### RuntimePolicy v1 — `QCS-H15-suspicious-filename/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h15-fim-create
spec:
  base-policy: file-create
  action: audit
  monitor-paths:
  - /tmp/citi-h15/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h15-fim-write
spec:
  base-policy: file-write
  action: audit
  monitor-paths:
  - /tmp/citi-h15/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h15-fim-rename
spec:
  base-policy: file-rename
  action: audit
  monitor-paths:
  - /tmp/citi-h15/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h15-fim-delete
spec:
  base-policy: file-delete
  action: audit
  monitor-paths:
  - /tmp/citi-h15/
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h15-fim-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /tmp/citi-h15/
```

### RuntimePolicy v2 — `QCS-H15-suspicious-filename/policy.yaml`

```yaml
# QCS-H15 — Suspicious Filename and File Integrity Monitoring
#
# FIM over a monitored dir. All fileOperations on the selected filenames
# are recorded with path + operation + process + parent + container.
# Alerting basis: the policy match (dir prefix + operation), not filename
# magic — the event carries the filename, the RULE decides what to watch.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h15-fim
spec:
  rules:
  - name: fim-create
    type: file
    id: fim-create
    fileOperation: create
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h15/
  - name: fim-write
    type: file
    id: fim-write
    fileOperation: write
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h15/
  - name: fim-rename
    type: file
    id: fim-rename
    fileOperation: rename
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h15/
  - name: fim-delete
    type: file
    id: fim-delete
    fileOperation: delete
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h15/
  - name: fim-open
    type: file
    id: fim-open
    fileOperation: open
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /tmp/citi-h15/
```

### Workload manifest (pod.yaml) — `QCS-H15-suspicious-filename/pod.yaml`

```yaml
# QCS-H15 — Suspicious Filename and File Integrity Monitoring
# CRS version support: 1.45+ — v1 file base-policies cover full FIM
#
# Creates, modifies, renames, reads, deletes, and re-creates the monitored
# filenames (login.jsp, Sql.java, package.json) under /tmp/citi-h15 —
# one of them re-created through a child/runtime script.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h15
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h15-workload
  namespace: citi-h15
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      mkdir -p /tmp/citi-h15
      cd /tmp/citi-h15
      echo "page-v1" > Login.jsp
      echo "class-v1" > Sql.java
      echo '{"name":"pkg"}' > package.json
      echo "page-v2" > Login.jsp              # modify
      mv Sql.java SqlOld.java                  # rename
      cat package.json                         # read
      rm SqlOld.java                           # delete
      # re-create through a child process (runtime script)
      sh -c 'echo "page-v3" > /tmp/citi-h15/Login.jsp'
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

| Operation | Hook | Process (parent) |
|---|---|---|
| create (3 files) | `security_inode_create` | bash |
| write (modify) | `vfs_write` | bash |
| rename | `security_path_rename` | mv (parent: bash) |
| read | `security_file_open` | cat (parent: bash) |
| delete | `security_path_unlink` | rm (parent: bash) |
| re-create via child | `security_file_open`/`vfs_write` | sh (parent: bash) |

Every event carried the resolved path (`/tmp/citi-h15/Login.jsp` …) and
container id; create/rename/delete hooks carry their target in dentry args.

### Observed data (v1 run)

Converted + load-verified, **spot-checked live**: all 5 v1 file hooks fired (`security_inode_create`, `vfs_write`, `security_file_open`, `security_path_rename`, `security_path_unlink`).

---

## QCS-H16-policy-enforcement

### QCS-H16 — Runtime Policy Enforcement / Process Blocking

**Hypothesis.** Qualys can move from audit-only monitoring to actually stopping a process
that violates a runtime policy — and the pod keeps running throughout.

**Verdict.** **Supported.** The same process rule in audit mode logged the probe
execution and let it run (`rc=0`); switched to `action: block` the probe
was SIGKILLed at exec (`rc=137`, `KPROBE_ACTION_SIGKILL` on
`security_bprm_check`) while the pod continued to run normally.

**CRS version support: 1.46+** — v2 process rule blocks exec (v1 action kill covers file ops only)

### RuntimePolicy v1 — `QCS-H16-policy-enforcement/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — enforcement exists only as action: kill on file
# operations; there is NO process-exec base-policy, so the exec-block
# leg of H16 cannot be expressed in v1 (same gap as H02/H03).
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h16-probe-block
spec:
  base-policy: file-open
  action: kill
  monitor-paths:
  - /tmp/citi-h16-probe.sh
```

### RuntimePolicy v2 — `QCS-H16-policy-enforcement/policy.yaml`

```yaml
# QCS-H16 — Runtime Policy Enforcement / Process Blocking
#
# The SAME policy shape in two modes: audit (process rule, action: audit)
# vs enforce (action: block). Blocking on a process rule hooks
# security_bprm_check — the exec is stopped before it commits (SIGKILL,
# rc=137). The pod itself stays up; only the violating process dies.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h16-probe-audit
spec:
  rules:
  - name: probe-exec-audit
    type: process
    id: probe-exec-audit
    action: audit
    matchBinaries:
    - operator: In
      values:
      - /tmp/citi-h16-probe.sh
---
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h16-probe-enforce
spec:
  rules:
  - name: probe-exec-block
    type: process
    id: probe-exec-block
    action: block
    matchBinaries:
    - operator: In
      values:
      - /tmp/citi-h16-probe.sh
```

### Workload manifest (pod.yaml) — `QCS-H16-policy-enforcement/pod.yaml`

```yaml
# QCS-H16 — Runtime Policy Enforcement / Process Blocking
# CRS version support: 1.46+ — v2 process rule blocks exec (v1 action kill covers file ops only)
#
# Disposable pod: drops a harmless probe script, runs it, then keeps
# sleeping so pod stability can be observed while the enforcement policy
# kills the probe on re-exec.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h16
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h16-workload
  namespace: citi-h16
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      printf '#!/bin/sh\necho CITI-H16-PROBE-RAN\nexit 0\n' > /tmp/citi-h16-probe.sh
      chmod +x /tmp/citi-h16-probe.sh
      echo "== audit mode: first run =="
      /tmp/citi-h16-probe.sh
      echo "probe-rc=$?"
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

| Phase | Probe result | Pod stability |
|---|---|---|
| audit | `CITI-H16-PROBE-RAN`, rc=0 | still alive |
| enforce | killed at exec, rc=137 | still alive |

Enforce event: `process_kprobe | citi-h16-probe-enforce-v2-probe-exec-block |
security_bprm_check | action=KPROBE_ACTION_SIGKILL`.

### Observed data (v1 run)

Converted + load-verified. Exec-block leg not expressible in v1 (`file-open` + `action: kill` approximates it); v1 `action: kill` covers file ops only.

---

## QCS-H17-deleted-pod-retention

### QCS-H17 — Deleted Pod Historical Activity and Event Retention

**Hypothesis.** After a pod and its container no longer exist, is the runtime evidence of
what it did still available and searchable?

**Verdict.** **Supported.** A short-lived container ran a file + process + network
sequence, was force-deleted, and its **11 events remained in the event
stream**, searchable by the recorded container id (and by a unique marker
in the command line). Retention *duration* is a platform setting (e.g.
the 7-day window referenced in the hypothesis) — the sensor itself does
not delete evidence with the pod.

**CRS version support: 1.45+** — v1 file-open + net-tcp-open cover evidence

### RuntimePolicy v1 — `QCS-H17-deleted-pod-retention/policy-v1.yaml`

```yaml
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h17-payload-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /tmp/citi-h17-payload.txt
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h17-egress-audit
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "8080"
```

### RuntimePolicy v2 — `QCS-H17-deleted-pod-retention/policy.yaml`

```yaml
# QCS-H17 — Deleted Pod Historical Activity and Event Retention
#
# Records the evidence-generating activity of the short-lived workload so
# that after it is deleted the events can be searched back by the recorded
# identifiers. (Retention WINDOW itself is a platform setting — the sensor
# writes events to the configured export/backend; nothing here is deleted
# with the pod.)
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h17-evidence
spec:
  rules:
  - name: payload-open
    type: file
    id: payload-open
    fileOperation: open
    action: audit
    matchFilePaths:
    - operator: Postfix
      values:
      - citi-h17-payload.txt
  - name: egress-audit
    type: network
    id: egress-audit
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "8080"
```

### Workload manifest (pod.yaml) — `QCS-H17-deleted-pod-retention/pod.yaml`

```yaml
# QCS-H17 — Deleted Pod Historical Activity and Event Retention
# CRS version support: 1.45+ — v1 file-open + net-tcp-open cover evidence
#
# Short-lived Job that runs a known sequence (file + process + network)
# then completes. After it is gone, events must still be searchable by
# the recorded pod UID / container ID / image digest.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h17
---
apiVersion: batch/v1
kind: Job
metadata:
  name: citi-h17-burst
  namespace: citi-h17
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 60
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: burst
        image: registry.access.redhat.com/ubi9/ubi-minimal:latest
        command:
        - sh
        - -c
        - |
          echo "payload CITI-H17-$(date +%s)" > /tmp/citi-h17-payload.txt
          cat /tmp/citi-h17-payload.txt
          # network leg: wget to the internal test endpoint
          wget -q -T 3 -O /dev/null http://citi-h17-svc:8080/ 2>/dev/null || true
          echo "CITI-H17-DONE"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          runAsNonRoot: true
          seccompProfile:
            type: RuntimeDefault
```

### Observed data (v2 run)

- Container id `5599f23125a0…` — recorded *before* deletion.
- After deletion: **11 events** for that container remain: exec/exit of
  bash/date/cat/sleep (base stream) + 5 policy events (`payload-open` by
  cat, `egress-audit` to :8080).
- The payload marker (`CITI-H17-RETENTION`) is also searchable — events
  were recovered by marker even after the container id lookup.

### Observed data (v1 run)

Converted + load-verified (file-open + net-tcp-open pair).

---

## QCS-H18-signal-correlation

### QCS-H18 — Process, File, and Network Event Correlation

**Hypothesis.** Can Qualys reconstruct a full investigation sequence from separate runtime
signals — shell → script creation → script execution → file read → DNS →
network connection — rather than showing isolated events?

**Verdict.** **Supported at the sensor level.** The runtime sensor emits every leg of
the chain as events that **join cleanly** (exec_id/parent_exec_id +
container id + unique marker) into the exact sequence the hypothesis asks
for: `bash → create payload+script → script exec → cat reads payload →
getent DNS (UDP :53) → tcp_connect to :8080`. Whether the *platform UI*
offers a pre-joined investigation view is a Qualys product question — the
data to reconstruct it is complete.

**CRS version support: 1.46+** — v2 chain legs; DNS leg = future release (raw TP)

### RuntimePolicy v1 — `QCS-H18-signal-correlation/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — no process-exec base-policy (chain-exec leg has no
# v1 form); file + network legs expressed as v1.
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h18-payload-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /tmp/citi-h18-payload.txt
---
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h18-egress-audit
spec:
  base-policy: net-tcp-open
  action: audit
  monitor-dest-ports:
  - "8080"
```

### RuntimePolicy v2 — `QCS-H18-signal-correlation/policy.yaml`

```yaml
# QCS-H18 — Process, File, and Network Event Correlation
#
# Every leg of the chain is a separately-matched signal; the events are
# joined by exec_id/parent_exec_id + container id + a unique marker
# (CITI-H18-<n> appears in script and payload names). DNS is UDP —
# tcp_connect never sees it; the raw tracingpolicy-dns.yaml (ip_output,
# :53) covers that leg.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h18-chain
spec:
  rules:
  - name: chain-exec
    type: process
    id: chain-exec
    action: audit
    matchBinaries:
    - operator: In
      values:
      - /tmp/citi-h18-chain.sh
  - name: payload-open
    type: file
    id: payload-open
    fileOperation: open
    action: audit
    matchFilePaths:
    - operator: Postfix
      values:
      - citi-h18-payload.txt
  - name: egress-audit
    type: network
    id: egress-audit
    direction: egress
    action: audit
    matchPorts:
    - operator: In
      values:
      - "8080"
```

### Workload manifest (pod.yaml) — `QCS-H18-signal-correlation/pod.yaml`

```yaml
# QCS-H18 — Process, File, and Network Event Correlation
# CRS version support: 1.46+ — v2 chain legs; DNS leg = future release (raw TP)
#
# One pod runs the full chain: parent shell creates a runtime script and a
# synthetic payload, the script reads the payload, resolves an internal
# hostname (DNS), and uploads the payload to the controlled endpoint.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h18
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h18-workload
  namespace: citi-h18
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      MARKER="CITI-H18-7749"
      echo "payload-$MARKER" > /tmp/citi-h18-payload.txt
      cat > /tmp/citi-h18-chain.sh <<'SH'
#!/bin/sh
cat /tmp/citi-h18-payload.txt
getent hosts citi-h18-svc.citi-h18.svc.cluster.local 2>/dev/null || true
wget -q -T 3 --post-file /tmp/citi-h18-payload.txt -O /dev/null http://citi-h18-svc:8080/upload
SH
      chmod +x /tmp/citi-h18-chain.sh
      /tmp/citi-h18-chain.sh
      echo "CHAIN-DONE"
      sleep 3600
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Raw Cilium TracingPolicy fallback — `QCS-H18-signal-correlation/tracingpolicy-dns.yaml`

```yaml
# Raw Cilium TracingPolicy — DNS leg of the correlation chain. Lookups are
# UDP; ip_output with the skb arg (index 2) on DPort 53 catches the DNS
# packet. Same shape as H06's verified dns-audit policy.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: citi-h18-dns
spec:
  kprobes:
  - call: "ip_output"
    syscall: false
    args:
    - index: 2
      type: "skb"
    selectors:
    - matchArgs:
      - index: 2
        operator: "DPort"
        values:
        - "53"
      - index: 2
        operator: "Protocol"
        values:
        - "IPPROTO_UDP"
      matchActions:
      - action: Post
```

### Observed data (v1 run)

Converted + load-verified (file-open + net-tcp-open; DNS leg stays raw-TP — v1 has no UDP hook).

---

## QCS-H19-sensor-health

### QCS-H19 — Sensor Coverage and Health Failure Detection

**Hypothesis.** Qualys reports which nodes/workloads have a healthy runtime sensor, and
detects when monitoring is degraded or unavailable.

**Verdict.** **Supported — the sensor health cycle is real and observable.** A
deliberate sensor interruption produced a clean **event gap** (zero
events while the agent was down), and recovery restored the event flow.
Node-level "degraded / not reporting" status in the Qualys UI is the
platform's sensor-profile view of exactly this cycle.

**CRS version support: 1.45+** — v1 file-open health probe; degraded-node reporting = platform

### RuntimePolicy v1 — `QCS-H19-sensor-health/policy-v1.yaml`

```yaml
# RuntimePolicy v1 — closest form for a health probe: file-open on a
# binary each time it executes (the sensor's file hook).
apiVersion: qualys.com/v1
kind: RuntimePolicy
metadata:
  name: citi-h19-health-open
spec:
  base-policy: file-open
  action: audit
  monitor-paths:
  - /usr/bin/true
```

### RuntimePolicy v2 — `QCS-H19-sensor-health/policy.yaml`

```yaml
# QCS-H19 — Sensor Coverage and Health Failure Detection
#
# No runtime detection policy needed — this hypothesis is about the
# SENSOR ITSELF. Local proof of the health cycle: the agent on :54321
# (process_exec/exit baseline + policy events), the capture stream, and
# what an interruption looks like (event gap, agent log) and how recovery
# resumes events. Node-level "degraded/not reporting" status is a Qualys
# platform (sensor profile) + OpenShift DaemonSet view.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h19-health-probe
spec:
  rules:
  - name: health-exec
    type: process
    id: health-exec
    action: audit
    matchBinaries:
    - operator: In
      values:
      - /usr/bin/true
```

### Workload manifest (pod.yaml) — `QCS-H19-sensor-health/pod.yaml`

```yaml
# QCS-H19 — Sensor Coverage and Health Failure Detection
# CRS version support: 1.45+ — v1 file-open health probe; degraded-node reporting = platform
#
# Pod that performs a trivial health-probe exec (`true`) on a schedule so
# a healthy sensor shows a steady, searchable event flow — and an
# interrupted sensor shows a visible gap.
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h19
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h19-workload
  namespace: citi-h19
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command:
    - sh
    - -c
    - |
      while true; do /usr/bin/true; sleep 5; done
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
```

### Observed data (v2 run)

| Phase | Agent (:54321) | New policy events |
|---|---|---|
| baseline | up | 1 |
| outage | down | **0** (gap) |
| recovery | up | 1 (resumed) |

### Observed data (v1 run)

Converted + load-verified (`file-open` on the health binary).

---

## QCS-H20-volume-mount-monitoring

### QCS-H20 — Volume Mount Monitoring in Containers

**Hypothesis.** A Cilium/eBPF-Agent policy can watch volume mounts — both
the volumes a container receives at start (`docker run -v`) and mounts a
process performs inside a running container — and report who did it, to
what target, with what filesystem, and whether it succeeded.

**Verdict.** **Partially — and the split is sharp.** The raw `sys_mount`
kprobe policy captures **every runtime-driven mount at container start**
(the `-v` volume bind mount, overlay rootfs, proc/devpts/sysfs/cgroup2/
shm, resolv.conf/hostname/hosts, netns) with source, target, fstype,
flags and return value. But a `mount(2)` executed by a process **inside a
running container** produces no event in this build
(`release/v1.6-1-q5`), even though a kernel-level kprobe on
`__x64_sys_mount` fires for those calls and `sys_openat`/`vfs_read` events
from the same process are emitted. RuntimePolicy v2 cannot express the
mount syscall at all; its file rules do see reads inside mounted volumes.

**CRS version support:** n/a — raw Cilium TracingPolicy (`cilium.io/v1alpha1`)
syscall hook; v2 has no syscall rule type yet (see "Future implementation").

### Raw Cilium TracingPolicy — `QCS-H20-volume-mount-monitoring/tracingpolicy.yaml`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: citi-h20-volume-mount-monitoring
spec:
  kprobes:
  - call: "sys_mount"
    syscall: true
    return: true
    message: "mount() called in a container"
    args:
    - index: 0
      type: "string"   # source
    - index: 1
      type: "string"   # target
    - index: 2
      type: "string"   # filesystemtype
    - index: 3
      type: "uint64"   # mountflags
    returnArg:
      index: 0
      type: "int"      # 0 success / negative errno
    selectors:
    - matchActions:
      - action: Post
```

### RuntimePolicy v2 — `QCS-H20-volume-mount-monitoring/policy.yaml`

```yaml
# v2 cannot express the mount(2) syscall; this rule watches file activity
# inside a mounted volume (the mount target path), which DOES work
# in-container.
apiVersion: qualys.com/v2
kind: RuntimePolicy
metadata:
  name: citi-h20-volume-mount-monitoring
spec:
  rules:
  - name: mounted-volume-read
    type: file
    id: vol-read
    fileOperation: read
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /mnt/citi-h20/
  - name: mounted-volume-create
    type: file
    id: vol-create
    fileOperation: create
    action: audit
    matchFilePaths:
    - operator: Prefix
      values:
      - /mnt/citi-h20/
```

### Workload manifest (pod.yaml) — `QCS-H20-volume-mount-monitoring/pod.yaml`

```yaml
# Pod mounting a hostPath volume and performing file activity inside it,
# plus a privileged tmpfs mount (mount(2) needs CAP_SYS_ADMIN).
apiVersion: v1
kind: Namespace
metadata:
  name: citi-h20
---
apiVersion: v1
kind: Pod
metadata:
  name: citi-h20-workload
  namespace: citi-h20
spec:
  restartPolicy: Never
  containers:
  - name: workload
    image: registry.access.redhat.com/ubi9/ubi-minimal:latest
    command: ["sh", "-c", |
      echo h20-proof > /mnt/citi-h20/from-pod.txt
      cat /mnt/citi-h20/from-pod.txt
      mkdir -p /mnt/citi-h20-tmp
      mount -t tmpfs tmpfs /mnt/citi-h20-tmp
      echo h20-mount-proof > /mnt/citi-h20-tmp/proof.txt
      umount /mnt/citi-h20-tmp
      sleep 3600]
    volumeMounts:
    - name: hostdata
      mountPath: /mnt/citi-h20
    securityContext:
      privileged: true
  volumes:
  - name: hostdata
    hostPath:
      path: /var/qualys-poc/QCS-H20
      type: DirectoryOrCreate
```

### Observed data

| Case | sys_mount event? | Record |
|---|---|---|
| `docker run -v` volume mount | **Yes** | bind `source=/tmp/citi-h20-data` → container, `fstype=bind`, `flags=20480`, `ret=0` + full start sequence (overlay/proc/tmpfs/devpts/sysfs/cgroup2/mqueue/shm/resolv/hostname/hosts/netns) |
| file activity inside mounted volume | **Yes** | v2 `vol-read`: `vfs_read` on `/mnt/citi-h20/seed.txt` and `new.txt` by `/usr/bin/cat` |
| unprivileged in-container mount (EPERM) | **No** | mount(2) executed (rc=32), no event |
| `--cap-add SYS_ADMIN` in-container mount | **No** | mount succeeded, no event |
| `--privileged` bind of host `/` | **No** | mount succeeded, no event |
| host-side mount (control) | **Yes** | `tmpfs → /tmp/citi-h20-hostmnt`, `ret=0` |

Chase notes: kernel-level kprobe on `__x64_sys_mount` fires for the
in-container call; the process is in the execve map (nonzero ktime);
`sys_openat` + `vfs_read` events from the same process are emitted — so the
drop is in eBPF-Agent's generic-kprobe/tracepoint path for processes in
container cgroups. `unshare -m` (fresh mount namespace, host cgroup) fires
fine, so the discriminator is the container cgroup, not the namespace.
Docker container-id fields are empty in this environment.

Flag experiments (full case set re-run): `--enable-host-ns-filter=false`
(also with `--enable-pod-ns-filter=false`, `--enable-process-ns`) does
**not** change coverage — in-container mounts stay silent — but it fixes
attribution: runtime mounts are then correctly attributed to `/usr/bin/runc`
(vs `/usr/lib/systemd/systemd` with the default `true`) and host mounts to
`mount(1)`. `--enable-qualys-sensors` fails to start the agent
(`bpf_qualys_dnsr.o` load error on this kernel).

---
