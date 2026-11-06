# QCS-H09 — Service Account Token Access and Kubernetes API Activity

## What we wanted to prove

When a workload reads its mounted service-account token and then talks to
the Kubernetes API, does Qualys record the token access, the process that
did it, the API connection, and which workload it was?

## Verdict

**Covered now: yes for the runtime side.** The token-file opens and the
API connection are both recorded, each carrying the executing binary, its
parent, and the container/workload identity.

**Not covered (platform):** *what the API call was* (the URI) and
*whether it was allowed* (200/403) — both ride inside TLS and only exist
in the cluster's API audit log. Qualys proves the workload and the
connection; the audit log proves the request and the verdict.

## What we did

- Policy: file-open audit under the service-account mount + egress audit
  on the API ports (443/6443)
- Workload (cluster): a pod with token automount that read the
  `namespace` and `token` files and connected to an API listener on :6443

## What we observed

| Hypothesis asks for | Status |
| --- | --- |
| Token-file access recorded | Yes — one open event per file (`namespace`, `token`) |
| Executing process on the access | Yes — binary + parent on every event |
| API network connection | Yes — egress `tcp_connect` with full tuple |
| Workload identity | Container ID on every event; pod/namespace fields under k8s |
| Which API resource / namespace was queried | **No** — request body is inside TLS |
| Whether the API allowed it | **No** — 200/403 lives only in the API audit log |

## Caveats

- Paths match the **resolved** path: `/var/run` is a symlink to `/run`,
  so the recorded path is `/run/secrets/.../serviceaccount/token` — the
  policy lists both prefixes (same lesson as H01's mount-path gotcha).
- `open` fires once per file open — the right signal for "access"; `read`
  would fire per read() call.
- **v1 `1s`/pod rate limit:** the token reads (`cat`, `wc`) and the two
  API curls each ran back-to-back, so consecutive hits within 1s were
  dropped. `pod.yaml` now sleeps between the legs (same fix as QCS-H08);
  verified live — both API connects recorded ~2s apart, one file event
  per token-file read.
- Correlating token read → API connect → audit-log verdict is a join on
  the event IDs + container ID.

k8s run on the EC2 lab (`hypo-run.py --labs 9`, v1 mode, 2026-11-06):
**PROVEN** — 22 matching events in 54.1s: file-open events on the SA
mount + two `Network Activity` connects to the API (~2s apart, authorized
+ unauthorized calls both recorded).

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| S4 | K8s/OpenShift API audit logs available | **NOT COVERED live** | platform leg |
| E1 | Read SA namespace + token paths | **YES** | open events on the resolved `/run/...` paths |
| E2 | Authorized query (own namespace) | **YES** | `tcp_connect` → :6443 with attribution |
| E3 | Unauthorized query (other namespace) | **YES** | identical `tcp_connect` (403 is inside TLS — audit log only) |
| E4 | Token access / process / API connection / workload identity | **YES** | open events + egress + container id; pod/ns under k8s |
| E5 | Compare with API audit evidence | **NOT COVERED live** | platform leg |

**Not covered live:** S4/E5 (audit logs).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | file-open on the SA mount + egress on API ports |
| `pod.yaml` | SA (automount on) + read-only Role + namespaces + pod doing the queries |
| `RESULT.md` | this document |