# QCS-H10 — Cross-Namespace RBAC Access Attempt

## What we wanted to prove

When a workload queries the Kubernetes API in a namespace it's allowed to
see and then in one it's *not*, does Qualys capture the API connection and
the initiating process — for both the authorized and the denied call?

## Verdict

**Covered now: the runtime visibility side.** Every API-bound connection
is recorded with the initiating binary, parent, and container identity —
authorized and unauthorized calls produce identical events.

**Not covered (platform):** which call was denied (HTTP 403) exists only
in the Kubernetes/OpenShift API audit log. Qualys proves the workload and
the connection; the audit log proves the identity and the denial.

## What we did

- Policy: file-open audit on the service-account mount + egress audit on
  API ports 443/6443 (same pattern as QCS-H09)
- Workload (cluster): read the SA token (as an API client would), then
  made an allowed query and a denied query to the API port, plus one
  connection to an unreachable port

## What we observed

| Operation | Event recorded | What it shows |
| --- | --- | --- |
| Client reads SA token | file-open on the token path | binary + parent + container ID |
| Authorized query (source ns) | `tcp_connect` → :6443 | full tuple + attribution |
| **Denied** query (target ns) | `tcp_connect` → :6443 | **identical** to the authorized event |
| Unreachable API port (refused) | `tcp_connect` → refused port | also identical — attempt, not outcome |

The two lessons from earlier labs stack here:

- The connect event fires at SYN-send — success, refusal, and a later 403
  all look the same (H06/H07).
- API requests and responses ride inside TLS — the URI and the 403 never
  appear in any event.

## So where's the authorization verdict?

The Kubernetes/OpenShift **API audit log**. The join:

- Qualys event: WHO (container ID, binary, parent) + WHEN + dst=API
- Audit log: service-account identity + namespace + verb + resource +
  response status (403)

Together they answer the hypothesis fully.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| E1 | Query allowed resources in source namespace | **YES** | `tcp_connect` → API port (with token open by the client) |
| E2 | Attempt list/read in target namespace | **YES** | identical `tcp_connect` |
| E3 | OpenShift denies the unauthorized op | **NOT COVERED live** | 403 is HTTP-inside-TLS — only in API audit logs (platform) |
| E4 | Qualys captures API connection + initiating process | **YES** | `tcp_connect` with attribution + container id |
| E5 | Audit logs identify SA + authz result | **NOT COVERED live** | platform leg |

**Not covered live:** E3/E5 (audit logs).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | file-open on the SA mount + egress on API ports |
| `pod.yaml` | source + target namespaces, SA confined to source, pod doing allowed then denied queries |
| `RESULT.md` | this document |