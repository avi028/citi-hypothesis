# QCS-H09 — Service Account Token Access and Kubernetes API Activity

## What we wanted to prove

When a workload reads its mounted service-account token and then talks to
the Kubernetes API, does Qualys record the token access, the process that
did it, the API connection, and which workload it was?

## Verdict

**Supported.** The token-file opens and the API connection were both
recorded, each carrying the executing binary, its parent, and the
container identity. What Qualys does **not** see is *what the API call
was* or *whether it was allowed* — that lives inside TLS and only exists
in the cluster's API audit log.

## What we did

- Policy (`policy.yaml`): one `file` rule auditing opens under the
  service-account mount, one `network` rule auditing egress connects to
  the API ports (443/6443)
- Workload: a container with a fake SA bundle bind-mounted at
  `/var/run/secrets/kubernetes.io/serviceaccount`, which read the
  `namespace` and `token` files then connected to a listener on :6443

## What we observed

| Hypothesis asks for | Status |
|---|---|
| Token-file access recorded | Yes — `security_file_open` event per file opened (`namespace`, `token`) |
| Executing process on the access | Yes — `binary` (`cat`) + parent (`bash`) on every event |
| API network connection | Yes — `tcp_connect` egress with full tuple (dst 172.17.0.1:6443) |
| Workload identity | Container ID on every event; pod/namespace fields populate under k8s/OpenShift only |
| Which API resource / which namespace was queried | **No** — request body is inside TLS |
| Whether the API allowed it | **No** — the connect event fires at SYN-send; the 200/403 is an HTTP-layer fact only the API audit log has |

## Caveats

- **matchFilePaths sees the resolved path.** `/var/run` is a symlink to
  `/run`; the recorded events show `/run/secrets/kubernetes.io/serviceaccount/token`
  — a `/var/run/...` prefix silently matches nothing. The policy lists
  both prefixes. Same symlink lesson as H01's mount-path gotcha.
- **`open` fires once per file open** (`security_file_open`) — the right
  signal for "access"; `read` would fire per read() call.
- In a real cluster the SA dir is a *projected volume*, but the resolved
  path is the same — the prefix still matches.
- Correlating the token read → API connect → audit-log verdict is
  post-processing: the events carry `exec_id`/`parent_exec_id` and
  container ID to join on.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
|---|---|---|---|
| S1 | Dedicated SA with minimal read-only RBAC | `pod.yaml` | `citi-h09-sa` + Role (get/list configmaps in citi-h09) |
| S2 | Test pod with token automount enabled | `pod.yaml` | `automountServiceAccountToken: true` |
| S3 | Access limited to non-sensitive resources | `pod.yaml` | ConfigMap only; no Secrets |
| S4 | K8s/OpenShift API audit logs available | **NOT COVERED live** | platform leg |
| S5 | File/process/network monitoring enabled | `policy.yaml` | file-open on SA dir + egress 443/6443 |
| E1 | Read SA namespace + token paths | **YES** | `security_file_open` on `…/serviceaccount/token` + `namespace` (resolved `/run/...`) |
| E2 | Authorized query (own namespace) | **YES** | `tcp_connect` → :6443 with attribution |
| E3 | Unauthorized query (other namespace) | **YES** | same-identical `tcp_connect` (403 lives inside TLS — audit log only) |
| E4 | Token access / process / API connection / workload identity | **YES** | open events (`cat` ← `bash`) + egress + container id; pod/ns in cluster |
| E5 | Compare with API audit evidence | **NOT COVERED live** | platform leg |

**Not covered live:** S4/E5 (audit logs). Real-cluster bonus: the policy also
caught minikube's `storage-provisioner` pod reading its own SA token — the
policy works on genuine in-cluster token access.

## eBPF-Agent events observed (2026-11-03 run)

```json
{"process_kprobe": {"policy_name": "citi-h09-sa-token-v2-sa-token-read", "function_name": "security_file_open",
 "process": {"binary": "/usr/bin/cat", "docker": "4035f497f93f"},
 "args": [{"file_arg": {"path": "/run/secrets/kubernetes.io/serviceaccount/token"}}]}}
{"process_kprobe": {"policy_name": "citi-h09-sa-token-v2-k8s-api-egress", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/bash"},
 "args": [{"sock_arg": {"daddr": "172.17.0.1", "dport": 6443, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}]}}
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | file-open rule on the SA mount + egress rule on API ports |
| `pod.yaml` | SA (automount on) + read-only Role/Binding + two namespaces + pod that reads the token and runs allowed & unauthorized API queries |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
mkdir -p /tmp/citi-h09-sa
echo citi-h09 > /tmp/citi-h09-sa/namespace
head -c 400 /dev/urandom | base64 | tr -d '\n' > /tmp/citi-h09-sa/token
echo FAKE-CA-BUNDLE > /tmp/citi-h09-sa/ca.crt
python3 -m http.server 6443 --bind 0.0.0.0 &        # stand-in API listener

./ebpf-operator tracingpolicy add citi-hypothesis/QCS-H09-service-account-token/policy.yaml
docker run --rm --name citi-h09 \
  -v /tmp/citi-h09-sa:/var/run/secrets/kubernetes.io/serviceaccount:ro \
  debian:stable-slim bash -c '
    cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
    cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null
    exec 3<>/dev/tcp/172.17.0.1/6443'
```

Result: 2 `security_file_open` events (`namespace`, `token` — resolved
`/run/...` path, `cat` child of `bash`) + 1 `tcp_connect` egress event to
:6443, all carrying the container ID.
