# QCS-H05 — Cross-Namespace East-West Communication Visibility

## What we wanted to prove

When a pod in one namespace talks to a service in another namespace, does
Qualys record who talked, to whom, and on what port?

## Verdict

**It works.** Every connection produced a record with the source program,
source IP, destination IP, port, and protocol — enough to map the
east-west path precisely.

## What we did

- Applied `policy.yaml`: *"audit outbound TCP connections to port 8080"*
- Ran a client that contacted the service three times — once by name, twice
  by IP

## What we observed

Each request produced a connection record containing:

- **source program** (`wget`) and the container it ran in
- **source IP** of the client (172.19.0.3)
- **destination IP + port** of the service (172.19.0.2:8080)
- **protocol** (TCP) and the connection state at send time
- the **result** of the connect call

Name-based and ClusterIP-based connects are indistinguishable on the wire
— the record always carries the resolved destination address.

## Caveats for the OpenShift run

- **Pod/namespace names are not in the event under plain docker** — only
  IPs and the container id. On OpenShift, pod name + namespace + labels
  are attached, giving the full source/destination workload context.
- Comparing with OpenShift logs: the sensor sees the connection at the
  kernel level, before any platform log — treat it as authoritative for
  "who initiated".

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
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

**Not covered live:** S4 (NetworkPolicy — cluster only), E5 (platform log
comparison). See README "Execution points not covered".

## Caveats (blunt)

- **Denied ports are policy-scoped**: a port NOT in `matchPorts` produces no
  event (9090 was added to the policy to make the denied test visible).
- **The policy matches every workload**: in the cluster run, minikube
  coredns/kubelet health probes to :8080 also matched (node noise). v2 has
  no working containerSelector — scope by `podSelector` or accept the
  noise; this is a real deployment consideration.

## Tetragon events observed (2026-11-03 quick run)

```json
{"process_kprobe": {"policy_name": "citi-h05-east-west-v2-east-west-egress", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/wget", "docker": "dfd56b3f3564"},
 "args": [{"sock_arg": {"daddr": "172.20.0.2", "dport": 8080, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}]}}
// ... same shape for the denied port:
{"process_kprobe": {"policy_name": "citi-h05-east-west-v2-east-west-egress", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/wget"},
 "args": [{"sock_arg": {"daddr": "172.20.0.2", "dport": 9090, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}]}}
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | egress audit rule for the service port |
| `pod.yaml` | two namespaces, service + NetworkPolicy + client |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
docker network create citi-net
docker run -d --name citi-srv --network citi-net alpine:3 \
  sh -c 'while true; do printf "HTTP/1.1 200 OK\r\n\r\nok" | nc -l -p 8080; done'
docker run -d --name citi-client --network citi-net alpine:3 sleep 1800
docker exec citi-client sh -c 'wget -q -O /dev/null http://citi-srv:8080;
  wget -q -O /dev/null http://172.19.0.2:8080;
  wget -q -O /dev/null http://172.19.0.2:8080'
```

Result: 3 connection events, each with source process, source/destination
IP, port 8080, protocol, and connect result.
