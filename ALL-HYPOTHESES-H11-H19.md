# citi-hypothesis — Today's Work: H11–H19

This file covers the labs created and live-verified on 2026-10-30
(privilege escalation, image/integrity, response, and forensics themes).
H01–H10 live in `ALL-HYPOTHESES.md`; this is the H11–H19 subset plus the
three "discuss with Qualys" use cases.

For each lab: hypothesis, verdict, **CRS version support**, both policy
forms (v2 + v1), the workload manifest, and the observed data from the
live run.


## CRS version support (per lab)

- **1.45+** — fully covered by RuntimePolicy **v1** (no v2 needed)
- **1.46+** — requires RuntimePolicy **v2** (process rules, exec context,
  enforcement) — v1 cannot express it
- **future release** — needs a **raw Cilium TracingPolicy** hook that v2
  does not have (caps, memfd, UDP/DNS, custom hooks); also recorded under
  "Future implementation" in the RESULT.md of the affected lab

| Lab | Hypothesis (one line) | Verdict (v2) | CRS | v1 verified |
|---|---|---|---|---|
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

Converted + load-verified (`v1convert` → `tetra add`). No capability base-policy in v1 — `file-open` on the probe binary is the closest form.

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

## Discussion use cases (with Qualys)

Three additional asks were marked as "discuss with Qualys". Runtime-sensor
position for each:

### 1. Crypto-mining process detection — mechanism verified

Behavioral signature = known miner binary names + egress to mining-pool
ports. This is exactly H12 (binary match) + H05/H06 (egress) combined.
Verified live with `tools/miner-sim.yaml`: a copied binary named
`/tmp/xmrig` exec → `miner-exec` bprm event; connect to :3333 →
`pool-egress` tcp_connect event. High-CPU *telemetry* as a signal is a
platform/agent-metrics question, not a hook event.
CRS: mechanism needs v2 process rules → **1.46+**.

### 2. Asset inventory and package search — platform query

"Show me all pods running OpenSSL 1.1.1k" is an inventory query over
image-scan data + runtime association. The sensor's contribution is the
exec-event record (which container ran which binary — H12); the search
UI/API over image content is a Qualys platform capability.
CRS: platform feature — versioning is a Qualys product question.

### 3. Unauthorized software components — partial

"Runtime used a component not part of the image's approved design" needs
a **baseline** (approved image inventory) plus runtime exec/file signals.
The sensor provides the runtime half (any exec is an event — H12/H15);
the "doesn't belong" comparison against the approved image is a platform
inventory join. No real-time "unexpected component" alert exists at the
sensor level today.
CRS: runtime half 1.46+ (v2 exec rules); baseline comparison = platform.
