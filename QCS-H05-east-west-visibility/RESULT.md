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
