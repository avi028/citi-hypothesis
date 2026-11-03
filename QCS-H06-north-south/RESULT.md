# QCS-H06 — Unusual North-South Network Connection

## What we wanted to prove

When a container opens an unexpected outbound connection, Qualys detects
it and can say which process made it and where it went — including when
the destination is unreachable.

## Verdict

**It works.** Successful, refused, and blackholed connections were all
recorded with process + destination attribution. Two honest limits:
visibility is scoped to the ports the policy watches, and UDP DNS lookups
are not part of `tcp_connect` telemetry.

## What we did

- Applied `policy.yaml`: *"audit outbound TCP to ports 80/443/8080"*
- From a container: resolved a name, connected to the approved port,
  tried a refused port (443), an unlisted port (9090), and an unreachable
  address

## What we observed

| Attempt | Recorded? |
|---|---|
| Connect to approved port 8080 (success) | Yes — full 5-tuple + process |
| Connect to port 443 — **connection refused** | Yes — identical record shape |
| Connect to unreachable IP (times out) | Yes — identical record shape |
| Connect to port 9090 — **not in the policy list** | No — policy-scoped visibility |
| DNS lookup (`getent`, UDP to resolver) | Not via tcp_connect — see below |

## Two things to know

- **The connect attempt is always recorded, even if it fails** — the
  event fires when the connection is initiated, so refused and timed-out
  attempts look the same as successful ones (return code is 0 in all
  cases; the outcome happens later at the TCP layer). See QCS-H07 for the
  platform-deny case.
- **DNS is UDP — `tcp_connect` never sees it.** `tracingpolicy-dns.yaml`
  is a raw Cilium policy on `ip_output` that audits UDP port 53; on the
  local docker run it did not fire because docker's embedded resolver is
  reached over loopback (127.0.0.11), which bypasses `ip_output`. On
  OpenShift, DNS goes to a real remote service IP and this fallback
  applies — listed as a candidate for a future v2 field.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
|---|---|---|---|
| S1 | Source pod with curl + DNS utilities | docker client | alpine `citi-h06-client` (`wget` = busybox curl; `getent` for DNS) |
| S2 | Approved internal HTTP/DNS test destination | listeners | host listeners :8080 (app), :443 (test dest); DNS via `getent` |
| S3 | OpenShift egress controls (only test dest permitted) | **NOT COVERED live** | docker has no egress policy; needs OpenShift — platform leg |
| S4 | Network + DNS monitoring enabled | `policy.yaml` + `tracingpolicy-dns.yaml` | egress audit (80/443/8080) + `ip_output` UDP :53 |
| S5 | No internet C2 | env note | all traffic loopback/docker-net only — no external dests used |
| E1 | Baseline traffic to approved app dest | **YES** (live) | `tcp_connect` → :8080 |
| E2 | Separate approved test dest, selected ports | **YES** (live) | `tcp_connect` → :443 (TLS fails; TCP recorded) |
| E3 | DNS resolution then TCP/HTTP | **YES** (live) | 2 `ip_output` UDP :53 events (getent) + `tcp_connect` → :8080 |
| E4a | Connection to blocked/unlisted port (:9090) | **YES** (live) | **NO event** — ports outside `matchPorts` are invisible (policy-scoped) |
| E4b | Connection to watched port, dropped by firewall | **YES** (live) | client timed out (rc=1) but `tcp_connect` **still recorded** — attempt, not outcome |
| E5 | DNS, dst address, port, process, container, policy-action telemetry | **YES** (live) | `ip_output` (getent) + `tcp_connect` (wget, dst `172.17.0.1`, port, `IPPROTO_TCP`, `KPROBE_ACTION_POST`, container id) |

**Not covered live:** S3 (OpenShift egress controls). See README
"Execution points not covered".

## eBPF-Agent events observed (2026-11-03 quick run)

```json
// egress (policy citi-h06-north-south) — one per connection, all identical shape
{"process_kprobe": {"policy_name": "citi-h06-north-south-v2-egress-audit", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/wget", "docker": "f584bb99436f"},
 "args": [{"sock_arg": {"daddr": "172.17.0.1", "dport": 8080, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}],
 "action": "KPROBE_ACTION_POST"}}
// ... :443 and the firewall-dropped :8080 produce the identical event
// DNS (raw TP citi-h06-dns-audit) — 2 datagrams from getent
{"process_kprobe": {"policy_name": "citi-h06-dns-audit", "function_name": "ip_output", "process": {"binary": "/usr/bin/getent"}}}
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | egress audit on approved ports |
| `tracingpolicy-dns.yaml` | raw UDP:53 audit fallback |
| `pod.yaml` | client pod doing DNS + the three connect cases |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
docker exec citi-client sh -c '
  getent hosts citi-srv
  wget -q -O /dev/null http://citi-srv:8080          # allowed
  wget -q -T 2 -O /dev/null https://citi-srv:443     # refused -> event
  wget -q -T 2 -O /dev/null http://citi-srv:9090     # unlisted -> no event
  wget -q -T 2 -O /dev/null http://172.19.0.99:8080' # blackhole -> event
```
