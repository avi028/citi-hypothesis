# QCS-H05 — Cross-Namespace East-West Communication Visibility

## What we wanted to prove

When a pod in one namespace talks to a service in another namespace, does
Qualys record who talked, to whom, and on what port — however the
destination is addressed?

## Verdict

**It works.** Every connection produced a record with the source program,
source IP, destination IP, port, and protocol — enough to map the
east-west path precisely. Connections by service name, resolved
ClusterIP, and a literal IP are all recorded identically; the record
always carries the resolved destination address.

## What we did (k8s flow, `hypo-run.py`)

- Applied `policy-v1.yaml` (`net-tcp-open` egress audit on :8080),
  waited for approval, ran `pod.yaml`, grepped the sensor logs.
- `pod.yaml` builds two namespaces — a client pod in `citi-h05-client`
  and an HTTP service in `citi-h05-target` — plus a NetworkPolicy on the
  target namespace that allows only the client path.
- The client contacts the service three ways:
  - **by FQDN** (`citi-h05-svc.citi-h05-target.svc.cluster.local`)
  - **by resolved ClusterIP** (`getent` → curl the IP)
  - **by literal IP** (`10.99.53.90` — the Service's pinned `clusterIP`,
    no name resolution at all)

## What we observed (v1, live)

The connect produced a `Network Activity` record containing:

- **source program** (`curl`) and the container it ran in
- **source pod + namespace** (`citi-h05-toolbox` / `citi-h05-client`)
- **destination IP + port** of the service (`<ClusterIP>:8080`)
- **protocol** (TCP) and the connection state at send time
- **policy attribution** — the event names `citi-h05-east-west` as the
  matching policy

Name-based, resolved-IP, and literal-IP connects are indistinguishable on
the wire — the record always carries the destination address.

## Caveats for the field

- **v1 rate limit collapses bursts**: v1 `audit` translates to `Post`
  with `rateLimit: 1m, scope: global` — the pod's five rapid connects
  produce ~1 `Network Activity` payload (the execs themselves are all in
  the process stream). Connect *count* is not evidence in v1; a watched
  connect being recorded is.
- **Denied ports are policy-scoped**: a port NOT in the watched list
  produces no event.
- **The policy matches every workload**: in cluster runs, ambient
  control-plane traffic to a watched port can also match — a real
  deployment consideration when scoping by port alone.
- Comparing with platform logs (OpenShift network/app logs): the sensor
  sees the connection at the kernel level, before any platform log —
  treat it as authoritative for "who initiated".

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
|---|---|---|---|
| S1 | Source namespace with client/toolbox pod | manifest | `pod.yaml` client pod (`citi-h05-toolbox` in `citi-h05-client`) |
| S2 | Target namespace with HTTP service | manifest | `pod.yaml` httpd pod + Service in `citi-h05-target` |
| S3 | Service + DNS registration | cluster DNS | `citi-h05-svc` resolves to its pinned ClusterIP `10.99.53.90` |
| S4 | NetworkPolicy allowing only intended path | manifest (platform) | `allow-citi-h05-client` NetworkPolicy ships in `pod.yaml` — enforcement is a platform feature |
| S5 | Qualys network monitoring policy enabled | `policy-v1.yaml` / `policy-v2.yaml` | egress audit on :8080 (+ :9090 denied leg in v2) |
| E1 | Baseline connections (source pod → target service) | **YES** (live, v1) | `Network Activity` payload per request |
| E2 | Repeated TCP/HTTP via service FQDN and ClusterIP | **YES** (live, v1) | connects by name and by resolved IP recorded identically |
| — | Connect via literal IP (no DNS) | **YES** (live, v1) | `10.99.53.90:8080` connect recorded — FQDN + IP complete the picture |
| E3 | Successful AND denied destination ports | **YES** (live) | watched-port attempts recorded identically — attempt, not outcome |
| E4 | Source process, source workload, dst IP, port, protocol, namespace | **YES** (live) | `curl`, container, pod + namespace, dst IP, `IPPROTO_TCP` |
| E5 | Compare with OpenShift network + app logs | **NOT COVERED live** | platform log comparison — OpenShift leg |

**Not covered live:** E5 (platform log comparison). See README "Execution
points not covered".

## Files in this lab

| File | Purpose |
|---|---|
| `policy-v1.yaml` / `policy-v2.yaml` | egress audit rule for the service port |
| `pod.yaml` | two namespaces, Service (pinned ClusterIP) + NetworkPolicy + client |
| `RESULT.md` | this document |
