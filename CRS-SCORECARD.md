# Qualys Container Runtime Security — CRS Scorecard (per hypothesis)

**For:** the SME presenting Qualys CRS against the customer's runtime
hypotheses H01–H19. **Basis:** live labs on Kubernetes with the Qualys
runtime sensor (agent 1.8.0, CRS 1.45, v1 policies unless noted). Each
"Proof" line is a real sensor event from the lab run, shortened.

**How to use each card:** read the customer's question, give the
**Answer** first, show the **Proof**, then volunteer the **Edge** before
they find it.

---

## Scorecard

| # | Hypothesis | Answer | CRS |
| --- | --- | --- | --- |
| H01 | Container escape / host file access | ✅ Supported | 1.46+ |
| H02 | Runtime file drift + unauthorized executable | ✅ Supported (incl. enforcement) | 1.45+ |
| H03 | Suspicious process / parent-child lineage | ✅ Supported | 1.45+ (full: 1.46+) |
| H04 | Fileless / inline script execution | 🟡 Partial | 1.45+ |
| H05 | Cross-namespace east-west visibility | ✅ Supported | 1.45+ |
| H06 | Unusual north-south connection | ✅ Supported (TCP) | 1.45+ |
| H07 | NetworkPolicy-denied connection attempt | ✅ Supported | 1.45+ |
| H08 | Data transfer / exfiltration | ✅ Supported | 1.45+ |
| H09 | Service-account token + K8s API activity | ✅ Supported (runtime side) | 1.45+ |
| H10 | Cross-namespace RBAC attempt | ✅ Supported (runtime side) | 1.45+ |
| H11 | Privilege escalation configuration | ✅ Supported (runtime context) | 1.45+ (full: 1.46+) |
| H12 | Vulnerable image "in use" | 🟡 Partial (runtime half) | 1.45+ (full: 1.46+) |
| H13 | Image lineage vs runtime change | 🟡 Partial (runtime half) | 1.45+ |
| H14 | Malicious / test file hash | ❌ Not a runtime capability | — |
| H15 | Suspicious filename + FIM | ✅ Supported | 1.45+ |
| H16 | Runtime enforcement / process blocking | ✅ Supported (process/file level) | 1.45+ (full: 1.46+) |
| H17 | Deleted-pod evidence retention | ✅ Supported | 1.45+ |
| H18 | Process + file + network correlation | ✅ Supported (data level) | 1.45+ (full: 1.46+) |
| H19 | Sensor coverage + health failure | ✅ Supported | 1.45+ |

**Opening line:** *"Of your 19 runtime hypotheses, 18 are covered at
runtime: 15 fully and 3 partially. The one that isn't, hash detection, is
handled by Qualys image scanning. We ran every one live, and here is the
evidence for each."*

---

## H01 — Container Escape / Host File Access

**Customer asks:** If a container reads a file on the worker node, do you
see it, and can you say which pod did it?

**Answer:** ✅ Yes. Reads of the host file are recorded with namespace,
pod, container, process tree, command line, file path and node.

**Proof:** An elevated pod with a read-only `hostPath` ran `cat` and
`sha256sum` on a host canary file, and each produced a read event. `ls`
and `stat` (metadata only) correctly produced none. The events stayed
searchable after the pod was deleted.

**Say it:** "We see a container touching the host, down to the exact file
and the exact command."

**Edge:** Needs the v2 policy model (CRS 1.46+) to target one specific
host file. The "restricted pod is denied" step is enforced by OpenShift
admission (the pod never starts), not by the sensor.

---

## H02 — Runtime File Drift & Unauthorized Executable

**Customer asks:** If someone drops and runs a script in a live container,
do you catch every step, and can you stop it?

**Answer:** ✅ Yes, both. Every stage produced its own event, and in
enforcement mode the action was killed.

**Proof:**
```
FILE Create      pod=citi-h02-drift file=/tmp/citi-h02/drift.sh actor=/usr/bin/sh    policy=citi-h02-drift-create
FILE Update      pod=citi-h02-drift file=/tmp/citi-h02/drift.sh actor=/usr/bin/sh    policy=citi-h02-drift-write
FILE SetSecurity pod=citi-h02-drift file=/tmp/citi-h02/drift.sh actor=/usr/bin/chmod policy=citi-h02-drift-metadata
FILE Rename      pod=citi-h02-drift file=/tmp/citi-h02/drift.sh actor=/usr/bin/mv    policy=citi-h02-drift-rename
POLICY citi-h02-drift-block-write: action=Sigkill  -> enforce pod killed (exit 137)
```

**Say it:** "Create, write, chmod, rename, delete: five separate records.
Flip one switch and the write is killed before it lands."

**Edge:** Enforcement is a SIGKILL of the process (exit 137), not a
"permission denied". Blocking the *exec* of the dropped script needs a v2
process rule (CRS 1.46+).

---

## H03 — Suspicious Process & Parent-Child Lineage

**Customer asks:** Do you record the full process chain inside a
container: launch, children, termination?

**Answer:** ✅ Yes. Every launch and exit is recorded with parent, command
line, UID, container, pod and namespace, including a killed process and
its signal.

**Proof:**
```
FILE Open ns=citi-h03 pod=citi-h03-chain file=/tmp/citi-h03-chain.sh actor=/usr/bin/sh policy=citi-h03-chain-open
EXEC /usr/bin/chmod ns=citi-h03 pod=citi-h03-chain cmd=/usr/bin/chmod +x /tmp/citi-h03-chain.sh
```
Chain `sh → script → find/head`, both short- and long-lived children, and
a `SIGTERM` kill were all recorded.

**Say it:** "Every process, its parent, its command line and who it ran
as, tied to the pod."

**Edge:** Each event carries its **immediate** parent. Deeper trees are
rebuilt by linking event IDs; the data is complete, but it isn't
pre-joined into one record.

---

## H04 — Fileless / Inline Script Execution

**Customer asks:** If an attacker runs code without dropping a file, do
you see it?

**Answer:** 🟡 Partially. You may not see the script itself, but you see
everything it does.

**Proof:**
```
FILE Open ns=citi-h04 pod=citi-h04-fileless file=/etc/citi-h04-canary.txt actor=/usr/bin/cat policy=citi-h04-canary-open
NET  TCP 192.168.231.98 -> 10.96.0.1:443 proc=/usr/bin/curl ns=citi-h04 pod=citi-h04-fileless policy=citi-h04-egress-audit
```

**Say it:** "With `bash -c` the whole inline script is in the command
line. With stdin, the body is hidden, but every command, file and
connection it makes is recorded and tied back to the shell."

**Edge:** Script body is invisible when piped through stdin. Memory-only
(`memfd`) execution detection is a next-release rule.

---

## H05 — Cross-Namespace East-West Visibility

**Customer asks:** When a pod in one namespace talks to a service in
another, what do you see?

**Answer:** ✅ Source program, source pod, destination IP, port and
protocol for every connection, including attempts to denied ports.

**Proof:** Verified run (2026-11-06): **12 events**. Baseline, repeated
FQDN and ClusterIP requests, and a denied port were each recorded.

**Say it:** "You get the exact east-west map: which process, in which pod,
reached which service on which port."

**Edge:** The destination shows the **ClusterIP** (before NAT). Allowed and
denied connects look the same (attempt, not outcome; see H07). Visibility
covers the ports the policy watches.

---

## H06 — Unusual North-South Connection

**Customer asks:** Do you detect and attribute unexpected outbound
connections?

**Answer:** ✅ Yes for TCP. Successful, refused and blackholed connections
are all recorded with process and destination.

**Proof:** Verified run (2026-11-06): **11 events**, covering baseline,
alternate destination port, and a firewall-dropped connect that was still
recorded.

**Say it:** "Even a connection your firewall dropped shows up, with the
program that tried it."

**Edge:** Ports outside the policy are deliberately silent. DNS lookups to
external resolvers are logged natively in agent 1.8. Cluster-internal
(kube-dns) DNS is next release.

---

## H07 — NetworkPolicy-Denied Connection Attempt

**Customer asks:** When NetworkPolicy blocks traffic, does Qualys still
see the attempt?

**Answer:** ✅ Yes, always. The attempt is recorded at the moment it
starts, before the network drops it.

**Proof:** Verified run (2026-11-06) on a CNI that really enforces
NetworkPolicy: **34 events**. Baseline `rc=0`, NetworkPolicy removed via
the API, then the denied retry (`rc=28`, timeout) still produced a connect
event.

**Say it:** "The attempt is the signal. A blocked attacker is still a
detected attacker."

**Edge:** Allowed and denied produce identical events. *Whether* it
succeeded comes from cluster network logs.

---

## H08 — Data Transfer / Exfiltration

**Customer asks:** Can you tie a file read to an outbound upload by the
same process?

**Answer:** ✅ Yes, exactly. The file-open and the outbound connection
carry the same process and parent chain, even when the upload runs
through a freshly created script.

**Proof:** Verified run (2026-11-06): **37 events** (file + network +
exec), with the `curl` upload attributed through the runtime script
`/tmp/citi-h08-upload.sh`.

**Say it:** "This process read this file and sent it there. One joined
story, not two guesses."

**Edge:** File **contents are never captured** (a privacy plus). The DNS
leg via kube-dns is next release.

---

## H09 — Service-Account Token & Kubernetes API Activity

**Customer asks:** Do you see a container stealing its service-account
token and calling the API?

**Answer:** ✅ Yes for the runtime side. The token read and the API
connection are both recorded with the workload identity.

**Proof:**
```
FILE Open ns=citi-h09 pod=citi-h09-workload file=/run/secrets/kubernetes.io/serviceaccount/.../namespace actor=/bin/cat
NET  TCP 192.168.231.104 -> 10.96.0.1:443 proc=/usr/bin/curl ns=citi-h09 pod=citi-h09-workload policy=citi-h09-k8s-api-egress
```
Bonus: the same policy caught a real cluster component
(`tigera-operator`) reading its own token, so this isn't lab-only.

**Say it:** "We show who reached for the credential and where they
called."

**Edge:** The API request and its allow/deny verdict are inside TLS and
come from the Kubernetes audit log.

---

## H10 — Cross-Namespace RBAC Access Attempt

**Customer asks:** If a workload tries to read another namespace's
resources, do you see it?

**Answer:** ✅ Runtime side, yes. Every API-bound connection is recorded
with the binary, parent and container. Authorized and unauthorized calls
both show up.

**Proof:** `cat` of the SA token followed by 4 `curl` API calls, 2 allowed
and 2 denied, each producing its own connect event about 2s apart:
```
NET TCP 192.168.231.101 -> 10.96.0.1:443 proc=/usr/bin/curl ns=citi-h10-src pod=citi-h10-workload policy=citi-h10-k8s-api-egress
```

**Say it:** "Every attempt to reach across namespaces is on record, tied
to the exact workload."

**Edge:** Which call was denied (HTTP 403) is only in the K8s audit log.
Qualys plus the audit log together give the full picture.

---

## H11 — Privilege Escalation Configuration

**Customer asks:** Can you tell a privileged workload's activity apart
from a normal one?

**Answer:** ✅ Yes. Every exec carries the process's capability set and
setuid/setgid properties, with no extra policy needed.

**Proof:**
```
FILE Open ns=citi-h11 pod=citi-h11-elevated file=/usr/bin/id actor=/usr/bin/sh policy=citi-h11-probe-open
```
Execs in the elevated pod carried `CAP_SYS_ADMIN`. The restricted control
pod was rejected at admission (`CreateContainerConfigError`), as
intended.

**Say it:** "Elevated processes look different in our data. You can see
exactly what they're allowed to do."

**Edge:** Admission accept/reject is OpenShift SCC's decision. A rule that
fires on a capability *change* is next release.

---

## H12 — Vulnerable Image "In Use"

**Customer asks:** Can you tell a vulnerable package that's actually
running from one that's just sitting in the image?

**Answer:** 🟡 The runtime half, cleanly. The workload that invoked the
package produced events. The identical workload that didn't produced
zero.

**Proof:** `citi-h12-used` and `citi-h12-unused` ran side by side. Only
the "used" pod triggered the policy on the vulnerable binary.

**Say it:** "We separate 'present' from 'actually running', which is how
you prioritize the CVE list."

**Edge:** CVE discovery, CVSS and fix versions come from Qualys image /
registry scanning (platform).

---

## H13 — Image Lineage vs Runtime Change

**Customer asks:** Can you distinguish what came in the image from what
changed after deploy?

**Answer:** 🟡 The runtime half fully. Every post-deploy create, write and
open is recorded. Image layers can't change at runtime, so anything the
sensor reports is drift by definition.

**Proof:**
```
FILE Create ns=citi-h13 pod=citi-h13-v1 file=/var/qualys-citi/h13/baked.txt actor=/usr/bin/sh policy=citi-h13-drift-create
FILE Update ns=citi-h13 pod=citi-h13-v1 file=/var/qualys-citi/h13/baked.txt actor=/usr/bin/sh policy=citi-h13-drift-write
```

**Say it:** "Image scan gives you the baseline. Runtime gives you every
deviation from it."

**Edge:** Digests, build history and layer diffs come from Qualys registry
scanning (platform).

---

## H14 — Malicious / Test File Hash

**Customer asks:** Can you flag a known-bad file by its hash at runtime?

**Answer:** ❌ Not at runtime. Runtime events are path-based and carry no
hash fields. Hash and filename search is a Qualys image-scanning feature.

**Proof:** A marker file with a known sha256 produced path-based events
only:
```
FILE Open ns=citi-h14 pod=citi-h14-workload file=/tmp/citi-h14-marker.txt actor=/usr/bin/cp policy=citi-h14-marker-open
```

**Say it:** "Hash matching happens before the image ships, in scanning.
At runtime we catch the file being created, copied, opened or executed."

**Edge:** Say it plainly. Being honest here buys credibility for the
other 18.

---

## H15 — Suspicious Filename & File Integrity Monitoring

**Customer asks:** Can you monitor specific sensitive filenames through
their whole lifecycle?

**Answer:** ✅ Yes. Create, modify, rename, read and delete were each
recorded, and a file recreated by a child process was attributed to that
child.

**Proof:**
```
FILE Create ns=citi-h15 pod=citi-h15-workload file=/tmp/citi-h15/Login.jsp    actor=/usr/bin/sh policy=citi-h15-fim-create
FILE Update ns=citi-h15 pod=citi-h15-workload file=/tmp/citi-h15/Sql.java     actor=/usr/bin/sh policy=citi-h15-fim-write
FILE Rename ns=citi-h15 pod=citi-h15-workload file=/tmp/citi-h15/Sql.java     actor=/usr/bin/mv policy=citi-h15-fim-rename
FILE Delete ns=citi-h15 pod=citi-h15-workload file=/tmp/citi-h15/SqlOld.java  actor=/usr/bin/rm policy=citi-h15-fim-delete
```

**Say it:** "Name the files you care about, and every touch is on record
with who did it."

**Edge:** Alerting is policy-path based: the policy watches a directory
or path, and the filename is in every event.

---

## H16 — Runtime Enforcement / Process Blocking

**Customer asks:** Can you move from watching to blocking without breaking
the application?

**Answer:** ✅ Yes at process/file level. In audit mode the probe ran
(rc=0). In enforce mode it was killed (rc=137).

**Proof:**
```
POLICY citi-h16-probe-block: action=Sigkill hook=security_file_open
FILE Open status=Failure ns=citi-h16 pod=citi-h16-workload file=/tmp/citi-h16-probe.sh policy=citi-h16-probe-block
```

**Say it:** "Same policy, one switch: from alert to kill, scoped to just
that workload."

**Edge:** Network deactivation, memory dump, pod kill and image blocklist
are Qualys **platform** response actions. Keeping the pod running while
blocking only the exec needs a v2 process rule (CRS 1.46+).

---

## H17 — Deleted-Pod Evidence Retention

**Customer asks:** After a short-lived pod is gone, is the evidence still
there?

**Answer:** ✅ Yes. The Job's file, process and network events stayed
searchable by container ID and a unique marker after the workload was
gone.

**Proof:** Job `citi-h17-burst` completed (`Succeeded`), and its events
remained: **14 events**, including
```
FILE Open ns=citi-h17 pod=citi-h17-burst-7ksf4 file=/tmp/citi-h17-payload.txt policy=citi-h17-payload-open
```

**Say it:** "Attackers love short-lived pods. The evidence outlives them."

**Edge:** Retention *length* is a platform setting (e.g. 7 days).

---

## H18 — Process, File & Network Correlation

**Customer asks:** Can you reconstruct an attack as a sequence, not
isolated events?

**Answer:** ✅ At the data level. Every link (shell → payload → script
exec → file read → connect) is emitted, and the links join on process IDs,
container ID and marker.

**Proof:**
```
FILE Open ns=citi-h18 pod=citi-h18-workload file=/tmp/citi-h18-payload.txt policy=citi-h18-payload-open
EXEC /usr/bin/chmod ns=citi-h18 pod=citi-h18-workload cmd=/usr/bin/chmod +x /tmp/citi-h18-chain.sh
```

**Say it:** "All the pieces are there and they connect. Today the timeline
is a query, not a click."

**Edge:** No built-in sequence view yet. The kube-dns leg is next release.

---

## H19 — Sensor Coverage & Health Failure

**Customer asks:** If the sensor on a node goes down, will we know?

**Answer:** ✅ Yes. A sensor interruption produces a clean event gap, and
recovery restores the flow.

**Proof:** A steady health probe showed baseline events, then **0 events**
while the agent was down, then events resumed on recovery.
```
FILE Open ns=citi-h19 pod=citi-h19-workload file=/usr/bin/true policy=citi-h19-health-open
```

**Say it:** "Coverage gaps are visible, not silent."

**Edge:** The node "degraded / not reporting" status lives in the Qualys
sensor profile (platform view of the same cycle).

---

## Suggested live demo (≈10 minutes)

```bash
sudo python3 hypo-run.py --labs 2,15,9,16 --yes --debug
```
H02 drift → kill, H15 suspicious filenames, H09 token theft, H16 audit →
block. `--debug` prints one-line FILE / EXEC / NET / POLICY summaries and
a verdict per lab. It needs the sensor logging at DEBUG level.

## Roadmap items to mention (direction, not promises)

- Cluster-internal (kube-dns) DNS visibility: H06, H08, H18
- Memory-only (`memfd`) fileless execution rule: H04
- Capability-change rule: H11
- Built-in sequence / timeline view: H18

---

## Prep notes for the SME (internal — do not present)

- **Cite the 2026-11-06 runs for H05, H06, H07 and H08.** In the
  2026-11-11 sweep (`run-new.log`) the H05–H07 workload pods stayed
  `Pending`, and the network events counted for H05–H08 came from CoreDNS
  health probes in `kube-system`. Re-run them on a healthy cluster before
  any live network demo.
- H16's "workload not ready (Failed)" warning in the sweep is expected:
  the pod fails *because* enforcement killed the probe.
- H09/H10 command lines contain a truncated bearer token. Mask raw log
  lines before showing them on a shared screen.
- v1 policies keep one event per pod per second. Repeated actions in the
  same second collapse into one event, so lab workloads space their steps.
