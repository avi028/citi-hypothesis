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
- Workload (cluster): a pod with token automount that read the SA token,
  then made **four real API calls** to `kubernetes.default:443` — two
  authorized (list + get ConfigMaps in `citi-h10-src`, its SA's only
  scope) and two unauthorized (the same queries against `citi-h10-dst`,
  answered 403). Calls are spaced 2s apart so each produces an event
  under the v1 `1s`/pod rate limit (same fix as H08/H09).

## What we observed

Live on the EC2 cluster (2026-11-06), `hypo-run.py --labs 10` (v1
policies): **PROVEN — 20 matching events in 54.2s**, including the API
connects landing **~2s apart, one per call**:

| Operation | Event recorded | What it shows |
| --- | --- | --- |
| Client reads SA token | file-open on the token path | binary + parent + pod/ns + container ID |
| Authorized query #1 (list, source ns) | `Network Activity` → `kubernetes.default:443` | full tuple + attribution |
| Authorized query #2 (get, source ns) | `Network Activity` → :443, ~2s later | identical shape |
| **Denied** query #1 (list, target ns) | `Network Activity` → :443, ~2s later | **identical** to the authorized events |
| **Denied** query #2 (get, target ns) | `Network Activity` → :443, ~2s later | also identical — attempt, not outcome |

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
