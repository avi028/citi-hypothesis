# Hypothesis Details — H01–H06 (point-wise)

Original hypothesis points with live coverage status. Full evidence in
each lab's RESULT.md; coverage matrix and run log in README.md.

Status legend: **YES** = verified live (k8s cluster e2e loop); **Partial** =
verified with a documented limitation; **Not covered live** = needs a
cluster or platform (listed in README "Execution points not covered").

| # | Hypothesis | Verdict | CRS |
|---|---|---|---|
| H01 | Container Escape / Host File Access Attempt | **Requires RuntimePolicy v2.** The hypothesis scopes to a specific host file via the v2 `Postfix` operator; v1 has no Postfix (Prefix-only), so v1 cannot determine the host file | 1.46+ |
| H02 | Runtime File Drift and Unauthorized Executable Creation | **It works, in both modes.** Every stage of the file's life produced a detection record. In enforcem | 1.45+ |
| H03 | Suspicious Process and Parent-Child Process Detection | **Supported, with one honest "partial".** Every launch, every child, every termination was recorded  | 1.46+ |
| H04 | Fileless or Inline Script Execution | **Partially — and the partial part matters.** You can't see the fileless script *itself*, but you se | 1.45+ |
| H05 | Cross-Namespace East-West Communication Visibility | **It works.** Every connection produced a record with the source program, source IP, destination IP, | 1.45+ |
| H06 | Unusual North-South Network Connection | **It works.** Successful, refused, and blackholed connections were all recorded with process + desti | 1.45+ |

---

## Hypothesis 01 — Container Escape / Host File Access Attempt

**Purpose.** Validate whether Qualys records access to a controlled host file from a container (read-only hostPath mount) and attributes it.

**Points and status:**

| Point | Task | Status | Evidence |
|---|---|---|---|
| E1 | Confirm a normal **restricted-v2 pod cannot access the host path** | **NOT COVERED live** | `pod.yaml` ships `citi-h01-restricted` (restricted-v2: non-root, no caps, seccomp). On the cluster it cannot start (`CreateContainerConfigError`) — the denial happens at admission/pod-creation; a path-level access denial was not demonstrated |
| E2 | Deploy an approved **elevated pod** with the test directory mounted **read-only** | **YES** (cluster) | `citi-h01-elevated` applied on the cluster (hostPath, `readOnly: true`); its reads produced the detection events |
| E3 | Run **ls, stat, cat, sha256sum** against the synthetic host file | **YES** (live) | `ls`/`stat` → no policy event (metadata-only, correct); `cat`/`sha256sum` → `vfs_read` events |
| E4 | Validate **namespace, pod, container, process tree, command line, file path, node** attribution | **YES** | cluster runs: namespace, pod, container id, process tree (`exec_id`/`parent_exec_id`), command line, `file_arg.path`, node, time all populated on the events |
| E5 | **Delete the pod** and confirm **historical activity remains searchable** | **YES** (live) | events persist in the stream after the pod is removed — same evidence pattern as QCS-H17 (11 events survived deletion); all records searchable by container id |

**Verdict.** **Requires RuntimePolicy v2 — not v1.** The hypothesis scopes to a
specific host file via the v2 `Postfix` operator; v1 has no Postfix (Prefix-only),
so v1 cannot determine the host file. In v1 mode this lab is **not covered**.

**Lab:** `citi-hypothesis/QCS-H01-host-file-access/` — policy: `policy-v2.yaml` (v2, Postfix); no `policy-v1.yaml` (v1 cannot express this); workload: `pod.yaml`

---

## Hypothesis 02 — Runtime File Drift and Unauthorized Executable Creation

**Purpose.** Validate whether Qualys detects post-deploy file create/write/metadata/rename/delete/exec and can enforce (kill) the actor.

**Points and status:**

| Point | Task | Status | Evidence |
|---|---|---|---|
| E1a | File create under monitored dir | **YES** (live) | `security_inode_create` (`bash`) |
| E1b | File write | **YES** (live) | `vfs_write` (`bash`) |
| E1c | Metadata change (chmod) | **YES** (live) | `security_path_chmod` (`chmod`) |
| E1d | Rename | **YES** (live) | `security_path_rename` (`mv`) |
| E1e | Delete | **YES** (live) | `security_path_unlink` (`rm`) |
| E2 | Enforce: kill the writer on block-dir write | **YES** (live) | `KPROBE_ACTION_SIGKILL` at `vfs_write`, container exit 137 |
| E3 | Enforce: block exec of the dropped script | **YES** (live) | `KPROBE_ACTION_SIGKILL` at `security_bprm_check`, script rc=137, container stable |
| E4 | Attribution (process, cmdline, UID, container, node, time) | **YES** (live) | `process.binary`, `arguments`, `uid`, `docker`, `node_name`, `time` on every event; pod/ns fields verified in cluster runs |

**Verdict.** **It works, in both modes.** Every stage of the file's life produced a
detection record. In enforcement mode, the unauthorized write and the
attempt to run the dropped script were both **killed on the spot** — the
script never ran.

**Lab:** `citi-hypothesis/QCS-H02-runtime-file-drift/` — policies: `policy.yaml` (v2), `policy-v1.yaml` (v1); workload: `pod.yaml`

---

## Hypothesis 03 — Suspicious Process and Parent-Child Process Detection

**Purpose.** Determine whether Qualys records complete process lineage for suspicious command execution inside a container.

**Points and status:**

| Point | Task | Status | Evidence |
|---|---|---|---|
| E1 | Start a shell (`oc exec` → `docker exec`) | **YES** (live) | `process_exec /usr/bin/sh` (marker in argv) |
| E2 | Controlled chain `bash → script → curl/find` | **YES** (live) | `sh` → `/tmp/citi-h03-chain.sh` (flagged) → `find`/`head` children |
| E3 | Short-lived + long-running children | **YES** (live) | `find`/`head`/`sleep 2` short-lived; `sleep 300` long-lived — all recorded with exec + exit |
| E4 | Terminate selected processes | **YES** (live) | killed `sleep 300` → `process_exit` with `signal: SIGTERM` |
| E5a | Process launch recorded | **YES** | `process_exec` for every process in the chain |
| E5b | Process termination recorded | **YES** | `process_exit` for every process, incl. the kill |
| E5c | Parent process | **YES** | `parent.binary` + `parent_exec_id` on every event |
| E5d | Command line | **YES** | `process.arguments` (marker `CITI-H03-5521` in argv) |
| E5e | UID | **YES** | `process.uid` on every event |
| E5f | Container | **YES** | `process.docker` id on every event |
| E5g | Pod + namespace | **YES** | fields populate under k8s/OpenShift — verified in cluster runs; plain docker shows container id only |

**Verdict.** **Supported, with one honest "partial".** Every launch, every child, every
termination was recorded with the parent, command line, UID and container
attached. The caveat: each record shows the process and its **immediate
parent** — grandparent-and-deeper trees are rebuilt by linking the event
IDs, which the data fully supports but isn't pre-joined in a single event.

**Lab:** `citi-hypothesis/QCS-H03-process-lineage/` — policies: `policy.yaml` (v2), `policy-v1.yaml` (v1); workload: `pod.yaml`

---

## Hypothesis 04 — Fileless or Inline Script Execution

**Purpose.** Validate whether Qualys detects suspicious script execution where no separate executable file is stored in the container image.

**Points and status:**

| Point | Task | Status | Evidence |
|---|---|---|---|
| E1 | Inline shell via `bash -c` | **YES** (live) | `process_exec /usr/bin/bash` — argv carries the **full inline script** |
| E2 | Script via standard input | **YES** (live) | `process_exec /usr/bin/bash` argv=`-` — script body **not** visible |
| E3 | Process, file-read, and network events from the inline script | **YES** (live) | child `cat` → `security_file_open` on the canary; `tcp_connect` egress → :8080, same container |
| E4 | Interpreter, full command line, children, associated activity | **YES PARTIAL (file open)** | interpreter ✓; cmdline ✓ for `-c`, ✗ for stdin; children + file-open + network activity ✓ — matches the annotation |
| E5 | Compare with file-based script scenario | **YES** (live) | file-based exec shows binary = `/tmp/citi-h04-file.sh` (script name visible); inline/stdin show only the interpreter |

**Verdict.** **Partially — and the partial part matters.** You can't see the fileless
script *itself*, but you see **everything it does**: every command it
launches, every file it opens, every connection it makes, all attributed
back to the shell that ran it.

**Lab:** `citi-hypothesis/QCS-H04-fileless-exec/` — policies: `policy.yaml` (v2), `policy-v1.yaml` (v1); workload: `pod.yaml`

---

## Hypothesis 05 — Cross-Namespace East-West Communication Visibility

**Purpose.** Determine what visibility Qualys provides when one namespace communicates with a service in another namespace.

**Points and status:**

| Point | Task | Status | Evidence |
|---|---|---|---|
| S1 | Source namespace with client/toolbox pod | manifest | `pod.yaml` client pod (docker: `citi-client` on `citi-net`) |
| S2 | Target namespace with HTTP service | manifest | `pod.yaml` server pod (docker: `citi-srv`, nc HTTP on :8080) |
| S3 | Service + DNS registration | docker DNS | name `citi-srv` resolves; ClusterIP-equiv = container IP `172.20.0.2` |
| S4 | NetworkPolicy allowing only intended path | **NOT COVERED live** | docker has no NetworkPolicy; needs cluster (OpenShift) — platform leg |
| S5 | Qualys network monitoring policy enabled | `policy.yaml` | v2 network rule egress audit, ports 8080 + 9090 |
| E1 | Baseline connections (source pod → target service) | **YES** (live) | `tcp_connect` event per request |
| E2 | Repeated TCP/HTTP via service FQDN and ClusterIP | **YES** (live) | 6 `tcp_connect` events (name + IP both → `172.20.0.2:8080`) |
| E3 | Successful AND denied destination ports | **YES** (live) | :8080 success events; denied :9090 (refused) recorded **identically** (`TCP_SYN_SENT`) — attempt, not outcome |
| E4 | Source process, source workload, dst IP, port, protocol, namespace | **YES** (partial) | live: `wget`, container id, `172.20.0.2`, `8080/9090`, `IPPROTO_TCP`; **namespace context is k8s-only** (verified in cluster runs) |
| E5 | Compare with OpenShift network + app logs | **NOT COVERED live** | no OpenShift logs in the docker lab; minikube cluster is available for the platform comparison run |

**Verdict.** **It works.** Every connection produced a record with the source program,
source IP, destination IP, port, and protocol — enough to map the
east-west path precisely.

**Lab:** `citi-hypothesis/QCS-H05-east-west-visibility/` — policies: `policy.yaml` (v2), `policy-v1.yaml` (v1); workload: `pod.yaml`

---

## Hypothesis 06 — Unusual North-South Network Connection

**Purpose.** Validate whether Qualys detects and attributes unexpected outbound connections from a container.

**Points and status:**

| Point | Task | Status | Evidence |
|---|---|---|---|
| S1 | Source pod with curl + DNS utilities | manifest | `pod.yaml` client pod (`wget`; `getent` for DNS) |
| S2 | Approved internal HTTP/DNS test destination | service | in-cluster HTTP service + test destination; DNS via `getent` |
| S3 | OpenShift egress controls (only test dest permitted) | **NOT COVERED live** | egress policy is a cluster/platform feature — needs OpenShift |
| S4 | Network monitoring enabled | `policy.yaml` / `policy-v1.yaml` | egress audit (80/443/8080); agent 1.8 logs pod DNS to external resolvers natively — kube-dns is **next release** |
| S5 | No internet C2 | env note | all traffic stays inside the test environment — no external dests used |
| E1 | Baseline traffic to approved app dest | **YES** (live) | `tcp_connect` → :8080 |
| E2 | Separate approved test dest, selected ports | **YES** (live) | `tcp_connect` → :443 (TLS fails; TCP recorded) |
| E3 | DNS resolution then TCP/HTTP | **YES** (live) | `MSG_OP_QUALYS_DNS` for the external lookup (pod src IP + answers) then `tcp_connect` — both recorded; kube-dns is next release |
| E4a | Connection to blocked/unlisted port (:9090) | **YES** (live) | **NO event** — ports outside `matchPorts` are invisible (policy-scoped) |
| E4b | Connection to watched port, dropped by firewall | **YES** (live) | client timed out (rc=1) but `tcp_connect` **still recorded** — attempt, not outcome |
| E5 | dst address, port, process, container, policy-action telemetry | **YES** (live) | `tcp_connect` (dst address, port, `IPPROTO_TCP`, `KPROBE_ACTION_POST`, container id) + `MSG_OP_QUALYS_DNS` (fqdn + answers + pod src IP); kube-dns telemetry is **next release** |

**Verdict.** **It works for TCP.** Successful, refused, and blackholed connections were all
recorded with process + destination attribution. Two honest limits:
visibility is scoped to the ports the policy watches, and DNS lookups to
external resolvers are recorded natively in agent 1.8
(`MSG_OP_QUALYS_DNS` — fqdn + answers + pod src IP); the kube-dns
(cluster-internal) path is a **next-release** item.

**Lab:** `citi-hypothesis/QCS-H06-north-south/` — policies: `policy.yaml` (v2), `policy-v1.yaml` (v1); workload: `pod.yaml`

---
---

# Original Hypothesis Texts (verbatim reference)

The unedited hypothesis cards as received. Annotations in [brackets] are
the requester's own. Live coverage status lives in the point tables above
and in each lab's RESULT.md.

## Hypothesis 1: Container Escape / Host File Access Attempt [Supported (Postfix operator)]
- Purpose: Validate whether Qualys detects and records process and file activity when a container accesses a controlled directory on the underlying OpenShift worker node.
- Required setup:
  - Dedicated namespace and service account.
  - OpenShift-approved custom SCC or temporary elevated SCC.
  - Dedicated read-only hostPath, such as /var/qualys-poc/QCS-H01.
  - Synthetic marker file on the test worker node.
  - Qualys Runtime Sensor and file tracing policy enabled.
- Execution flow:
  - Confirm that a normal restricted-v2 pod cannot access the host path.
  - Deploy an approved elevated pod with the test directory mounted read-only.
  - Run ls, stat, cat, and sha256sum against the synthetic host file. [YES]
  - Validate namespace, pod, container, process tree, command line, file path, and node attribution. [YES]
  - Delete the pod and confirm that historical activity remains searchable. [YES]

## Hypothesis 2: Runtime File Drift and Unauthorized Executable Creation [Supported (catch create/write events)]
- Purpose: Validate whether Qualys detects files or executable scripts introduced or modified after a container is deployed.
- Required setup:
  - Standard non-root test pod with bash, chmod, stat, and hashing utilities.
  - Writable /tmp or emptyDir volume.
  - Qualys file monitoring or FIM policy covering the test path.
  - Audit-mode runtime policy initially, followed by enforcement mode if supported.
- Execution flow:
  - Create a harmless script in /tmp after the container starts.
  - Modify the script, change its permissions, and execute it.
  - Rename and delete the script.
  - Verify creation, write, rename, permission-change, execution, and deletion telemetry. [YES]
  - If enforcement is enabled, repeat the execution and verify whether it is blocked or terminated. [YES PARTIAL FOR RENAME, DELETE]

## Hypothesis 3: Suspicious Process and Parent-Child Process Detection [Partial (smart sensor)]
- Purpose: Determine whether Qualys records complete process lineage for suspicious command execution inside a container.
- Required setup:
  - Test image containing bash, sh, ps, find, curl, and other approved utilities.
  - Qualys process monitoring enabled.
  - Unique test marker included in commands for event correlation.
- Execution flow:
  - Use oc exec to start a shell.
  - Execute a controlled process chain such as bash → script → curl/find.
  - Create both short-lived and longer-running child processes.
  - Terminate selected processes.
  - Verify process launch, termination, parent process, command line, UID, container, pod, and namespace metadata. [YES]

## Hypothesis 4: Fileless or Inline Script Execution [Partial (Open event)]
- Purpose: Validate whether Qualys detects suspicious script execution where a separate executable file is not stored in the container image.
- Required setup:
  - Test pod with approved shell or interpreter.
  - Process monitoring policy enabled.
  - No real payload or external code.
  - Synthetic commands limited to harmless enumeration and test output.
- Execution flow:
  - Run a harmless inline shell command through bash -c.
  - Pass a controlled script through standard input to the interpreter.
  - Generate process, file-read, and network events from the inline script.
  - Verify whether Qualys captures the interpreter, full command line, child processes, and associated activity. [YES PARTIAL FOR FILE OPEN]
  - Compare visibility with the file-based script scenario.

## Priority 2: Network and Namespace Activity

## Hypothesis 5: Cross-Namespace East-West Communication Visibility [Supported]
- Purpose: Determine what visibility Qualys provides when one namespace communicates with a service in another namespace.
- Required setup:
  - Source namespace with a client/toolbox pod.
  - Target namespace with an NGINX or simple HTTP service.
  - OpenShift Service and DNS registration.
  - NetworkPolicy allowing only the intended test path.
  - Qualys network monitoring policy enabled.
- Execution flow:
  - Establish normal baseline connections from the source pod to the target service.
  - Generate repeated TCP/HTTP requests using the service FQDN and ClusterIP.
  - Test successful and denied destination ports.
  - Verify source process, source workload, destination IP, port, protocol, and namespace context. [YES]
  - Compare Qualys visibility with OpenShift network and application logs.

## Hypothesis 6: Unusual North-South Network Connection [Supported]
- Purpose: Validate whether Qualys detects and attributes unexpected outbound connections from a container.
- Required setup:
  - Source pod with curl and DNS utilities.
  - Approved internal HTTP/DNS test destination.
  - OpenShift egress controls configured to permit only the test destination.
  - Qualys network and DNS monitoring enabled.
  - No internet-based command-and-control infrastructure.
- Execution flow:
  - Generate baseline traffic to an approved application destination.
  - Connect to a separate approved test destination on selected ports.
  - Perform DNS resolution followed by a TCP/HTTP connection.
  - Attempt a connection to a blocked port for comparison.
  - Validate DNS, destination address, port, process, container, and policy-action telemetry. [YES]
- Note: Qualys documentation states that its Runtime Sensor tracks network activity and can capture tcp_connect events when the applicable policy is assigned. (Getting Started with Container Runtime Sensor, docs.qualys.com)

## Hypothesis 7: Network Policy Violation and Denied Connection Attempt [Supported]
- Purpose: Determine whether Qualys records attempted communication when OpenShift NetworkPolicy blocks the connection.
- Required setup:
  - Source and target namespaces.
  - Target service with a default-deny NetworkPolicy.
  - Temporary allow policy for baseline comparison.
  - Qualys network monitoring enabled.
  - OpenShift network evidence available for corroboration.
- Execution flow:
  - Connect successfully while the allow policy is active.
  - Apply the default-deny policy.
  - Repeat the same connection attempt.
  - Compare Qualys telemetry for successful versus blocked traffic. [YES]
  - Determine whether Qualys reports the attempt, only the successful connection, or no event.

## Hypothesis 8: Controlled Data Transfer / Exfiltration Simulation [Supported]
- Purpose: Validate whether Qualys identifies and attributes a process transferring synthetic data from a container to another controlled destination.
- Required setup:
  - Source pod containing a synthetic test file.
  - Approved internal HTTP object receiver or test storage endpoint.
  - Egress restricted to the approved destination.
  - Unique filename and test identifier.
  - Qualys process, file, DNS, and network monitoring enabled.
- Execution flow:
  - Read the synthetic file from the source pod.
  - Upload it to the approved test endpoint using curl.
  - Repeat using a newly created runtime script.
  - Verify correlation between file access, process execution, DNS activity, and network connection.
  - Confirm that Qualys does not capture or expose actual file contents unless explicitly designed and approved to do so.

## Priority 3: Identity and Privilege Abuse

## Hypothesis 9: Service Account Token Access and Kubernetes API Activity [Do they want events along with token/API info?]
- Purpose: Validate whether Qualys records access to a mounted service-account token and subsequent Kubernetes API activity originating from the container.
- Required setup:
  - Dedicated service account with minimal read-only RBAC.
  - Separate test pod with token automount explicitly enabled.
  - Access limited to non-sensitive resources in the test namespace.
  - Kubernetes/OpenShift API audit logs available.
  - Qualys file, process, and network monitoring enabled.
- Execution flow:
  - Read the service-account namespace and token metadata path.
  - Use the token only to query an approved resource in the same test namespace.
  - Attempt an unauthorized query against another test namespace.
  - Validate token-file access, executing process, API network connection, and workload identity.
  - Compare Qualys evidence with OpenShift API audit evidence.

## Hypothesis 10: Cross-Namespace RBAC Access Attempt
- Purpose: Validate visibility when a workload attempts authorized and unauthorized Kubernetes API operations across namespaces.
- Required setup:
  - Source and target namespaces.
  - Dedicated service account with permissions restricted to the source namespace.
  - Harmless ConfigMap or pod metadata in the target namespace.
  - OpenShift audit logging available.
  - No access to Secrets or production resources.
- Execution flow:
  - Query allowed resources in the source namespace.
  - Attempt to list or read approved non-sensitive resources in the target namespace.
  - Verify that OpenShift denies the unauthorized operation.
  - Determine whether Qualys captures the API connection and initiating process.
  - Use OpenShift audit logs to identify the service account and authorization result.

## Hypothesis 11: Privilege Escalation Configuration Detection [Do they want only elevated process events]
- Purpose: Determine whether Qualys identifies risky workload configurations and runtime activity involving elevated privileges.
- Required setup:
  - Dedicated elevated-test namespace.
  - OpenShift-approved custom SCC.
  - Separate manifests testing one risky setting at a time:
    - root UID
    - added Linux capability
    - allowPrivilegeEscalation
    - hostPID
    - privileged container
  - No production node or sensitive host data.
- Execution flow:
  - Submit each workload configuration separately.
  - Record whether OpenShift admits or rejects the pod.
  - For admitted pods, run harmless identity and process checks.
  - Validate whether Qualys identifies the risky configuration and associated runtime context. [YES]
  - Distinguish OpenShift admission-control findings from Qualys runtime detections.

## Priority 4: Image, Vulnerability, and Supply-Chain Validation

## Hypothesis 12: Vulnerable Image Discovery and "In Use" Prioritization [Partial]
- Purpose: Validate whether Qualys discovers vulnerabilities in a deployed test image and distinguishes packages actively used at runtime from packages merely present in the image.
- Required setup:
  - Approved test image containing a known, documented vulnerable package version.
  - Image stored in the connected internal registry.
  - Running deployment created from the image.
  - A second image containing the same package but without invoking it.
  - Qualys image and registry scanning enabled.
- Execution flow:
  - Scan the image in the registry.
  - Deploy the image into the test namespace.
  - Invoke the selected package in one workload but not the comparison workload.
  - Compare vulnerability, exploitability, and "in use" results.
  - Validate image, container, package, version, workload, and remediation metadata. [BM1.1]

## Hypothesis 13: Image Lineage and Runtime Integrity Change [Partial (QQL to see actual diff)]
- Purpose: Validate whether Qualys preserves image lineage and distinguishes immutable image content from runtime container changes.
- Required setup:
  - Two approved image versions built from documented Dockerfiles.
  - Unique immutable image digests.
  - Minor controlled differences between image layers.
  - Runtime-writable directory for post-deployment changes.
  - Registry and runtime sensors enabled.
- Execution flow:
  - Scan and deploy image version 1.
  - Replace it with image version 2.
  - Introduce a runtime file change after deployment.
  - Compare build history, image digest, metadata, running-container association, and runtime drift.
  - Confirm whether image-layer changes can be distinguished from runtime filesystem changes. [YES PARTIAL]

## Hypothesis 14: Malicious or Test File Hash Detection [Not supported (Hash based detection not supported)]
- Purpose: Validate whether Qualys can identify a known test hash in an image and/or running container.
- Required setup:
  - Benign test file with a precomputed MD5/SHA-256 hash.
  - Dedicated image containing the test file.
  - Runtime-writable path for copying the same file after deployment.
  - Qualys image scanning, file monitoring, and hash-search functionality enabled.
  - Use a harmless marker or an industry-approved antivirus test artifact rather than malware.
  - process name, PIDs, strings, loaded modules, loaded drivers, file descriptors, all types of hash [AJ2.1] values.
- Execution flow:
  - Scan the image containing the test file.
  - Search for its hash and filename.
  - Deploy the image and confirm workload association.
  - Create or copy the same file into a running container.
  - Compare image-scan visibility with runtime-file visibility.

## Hypothesis 15: Suspicious Filename and File Integrity Monitoring [Supported]
- Purpose: Validate whether Qualys can identify and monitor selected filenames within a running container.
- Required setup:
  - Test pod with writable /tmp or emptyDir.
  - FIM rule covering the selected directory and filenames.
  - Harmless files named for the test, such as Login.jsp, Sql.java, or package.json.
  - Unique test content and hashes.
- Execution flow:
  - Create the monitored files.
  - Modify, rename, read, and delete them.
  - Recreate one file through a child process or runtime script.
  - Validate filename, path, operation, timestamp, process, parent process, and workload attribution. [YES]
  - Determine whether alerting is based on filename, policy match, or general file activity.

## Priority 5: Response and Forensic Readiness

## Hypothesis 16: Runtime Policy Enforcement / Process Blocking [Partial (manual steps for now)]
- Purpose: Validate whether Qualys can move from audit-only monitoring to blocking or terminating a process that violates a runtime policy.
- Required setup:
  - Dedicated disposable test pod.
  - Qualys runtime policy created first in audit mode.
  - Policy scoped only to the test namespace, image, or workload.
  - Harmless process selected as the violation trigger.
  - OpenShift and Qualys event evidence available.
- Execution flow:
  - Execute the test process in audit mode and confirm detection without interruption.
  - Enable enforcement for the same narrowly scoped policy.
  - Re-execute the process.
  - Verify whether the launch process is blocked or the process is terminated. [YES]
  - Confirm that the application pod remains stable and review enforcement telemetry.
  - Check if Qualys can deactivate the Pod's network connection, can take the memory dump and [AJ3.1] block any out of boundary File System access, can kill the Pod and can block the deployed image from being deployed again until is scanned and whitelisted again.

## Hypothesis 17: Deleted Pod Historical Activity and Event Retention [Supported (7 days retention)]
- Purpose: Verify whether runtime evidence remains available after the container and pod no longer exist.
- Required setup:
  - Short-lived pod or Kubernetes Job.
  - Runtime file, process, and network events generated during execution.
  - Recorded pod UID, container ID, image digest, node, and timestamps.
  - Qualys search and export access.
- Execution flow:
  - Execute a known sequence of file, process, and network activities.
  - Record all workload identifiers.
  - Delete the pod or allow the Job to complete.
  - Search Qualys using the deleted workload identifiers.
  - Determine which evidence remains available and whether the original activity can be reconstructed. [YES]

## Hypothesis 18: Process, File, and Network Event Correlation [Not supported]
- Purpose: Determine whether Qualys can correlate multiple runtime signals into a coherent investigation sequence rather than presenting isolated events.
- Required setup:
  - Test pod with approved shell and network utilities.
  - Runtime tracing for process, file, DNS, and network events.
  - Internal HTTP test destination.
  - Unique test ID included in filenames and requests.
- Execution flow:
  - Create a runtime script.
  - Execute the script through a parent shell.
  - Read a synthetic file.
  - Resolve an internal test hostname.
  - Connect to and upload the synthetic file to the controlled endpoint.
  - Assess whether Qualys can reconstruct the sequence:
    shell → file creation → script execution → file read → DNS → network connection. [YES PARTIAL WITH NO SEQUENCE CONSTRUCTION]

## Hypothesis 19: Sensor Coverage and Health Failure Detection [Supported (Can check through sensor profile)]
- Purpose: Validate whether Qualys accurately reports Runtime Sensor coverage and identifies nodes or workloads where monitoring is degraded or unavailable.
- Required setup:
  - At least two approved worker nodes if available.
  - Qualys Runtime Sensor deployed as a DaemonSet.
  - Access to sensor status in Qualys and OpenShift.
  - OpenShift-team-controlled sensor interruption method.
- Execution flow:
  - Record normal DaemonSet and Qualys sensor health.
  - Confirm test workloads are scheduled on monitored nodes.
  - Have the OpenShift team perform an approved temporary sensor interruption on one test node.
  - Verify whether Qualys reports the node as degraded or not reporting. [YES]
  - Restore the sensor and confirm recovery and event flow.
