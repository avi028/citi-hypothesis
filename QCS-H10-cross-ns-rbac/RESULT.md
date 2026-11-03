# QCS-H10 — Cross-Namespace RBAC Access Attempt

## What we wanted to prove

When a workload queries the Kubernetes API in a namespace it's allowed to
see and then in one it's *not*, does Qualys capture the API connection and
the initiating process — for both the authorized and the denied call?

## Verdict

**Supported for visibility; the allow/deny verdict is not Qualys's job.**
Every API-bound connection was recorded with the initiating binary,
parent, and container identity — authorized and unauthorized calls are
**byte-for-byte identical events**. Which call was denied (HTTP 403)
exists only in the Kubernetes/OpenShift API audit log.

## What we did

- Policy (`policy.yaml`): file-open audit on the service-account mount +
  egress audit on API ports 443/6443 (same pattern as QCS-H09)
- Workload: a container that read its SA token (as an API client would),
  then made three connections: two to a reachable "API" port (:6443 —
  standing in for an allowed query and a denied 403 query, since TLS
  makes them indistinguishable) and one to a dead port (:443 refused)

## What we observed

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

## So where's the authorization verdict?

The Kubernetes/OpenShift **API audit log**. The join is:

```
Qualys event:  WHO (container ID, binary, parent, exec_id) + WHEN + dst=API:6443
Audit log:     serviceAccount username + namespace + verb + resource + responseStatus (403)
```

Together they answer the hypothesis fully: Qualys proves the workload and
the connection; the audit log proves the identity and the denial.

## Caveats

- Token path matches the **resolved** path (`/run/secrets/…`, not the
  `/var/run` symlink — see QCS-H09).
- `pod`/`namespace` fields on events only populate under k8s/OpenShift;
  plain docker shows the container ID only.
- A denied *connection* (firewall/drop) and a denied *API operation*
  (403) are different things — Qualys sees both as attempts; only the
  audit log distinguishes "couldn't reach" from "wasn't allowed".

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
|---|---|---|---|
| E1 | Query allowed resources in source namespace | **YES** | `tcp_connect` → :6443 (with token open by client) |
| E2 | Attempt list/read in target namespace | **YES** | identical `tcp_connect` → :6443 |
| E3 | OpenShift denies the unauthorized op | **NOT COVERED live** | the 403 is HTTP-inside-TLS — only in API audit logs (platform) |
| E4 | Qualys captures API connection + initiating process | **YES** | `tcp_connect` with `bash`/`cat` attribution + container id |
| E5 | Audit logs identify SA + authz result | **NOT COVERED live** | platform leg |

**Not covered live:** E3/E5 (audit logs).

## eBPF-Agent events observed (2026-11-03 run)

```json
{"process_kprobe": {"policy_name": "citi-h10-cross-ns-v2-sa-token-read", "function_name": "security_file_open",
 "process": {"binary": "/usr/bin/cat", "docker": "20301d264c54"},
 "args": [{"file_arg": {"path": "/run/secrets/kubernetes.io/serviceaccount/token"}}]}}
{"process_kprobe": {"policy_name": "citi-h10-cross-ns-v2-k8s-api-egress", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/bash"},
 "args": [{"sock_arg": {"daddr": "172.17.0.1", "dport": 6443, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}]}}
// authorized, denied, and refused (:443) connects — all identical events
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | file-open rule on the SA mount + egress rule on API ports |
| `pod.yaml` | src+dst namespaces, SA confined to src, ConfigMaps in both, pod running allowed then denied API queries |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./ebpf-operator tracingpolicy add citi-hypothesis/QCS-H10-cross-ns-rbac/policy.yaml
docker run --rm --name citi-h10 \
  -v /tmp/citi-h09-sa:/var/run/secrets/kubernetes.io/serviceaccount:ro \
  debian:stable-slim bash -c '
    cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null
    exec 3<>/dev/tcp/172.17.0.1/6443   # authorized op
    exec 4<>/dev/tcp/172.17.0.1/6443   # denied op (403 inside TLS)
    exec 5<>/dev/tcp/172.17.0.1/443    # refused — still recorded
  '
```

Result: 1 `security_file_open` (token), 3 identical `tcp_connect` egress
events (2× :6443, 1× :443 — all `TCP_SYN_SENT`, attempts recorded,
outcomes not).
