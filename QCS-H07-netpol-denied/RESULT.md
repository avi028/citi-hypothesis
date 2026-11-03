# QCS-H07 — Network Policy Violation and Denied Connection Attempt

## What we wanted to prove

When the platform (NetworkPolicy / firewall) blocks a connection, does
Qualys still record the attempt — or only successful connections?

## Verdict

**The attempt is recorded, always.** Qualys sees the connection the
moment it is initiated — before the platform drops it — so denied flows
produce the same event as allowed ones. Whether it succeeded must be
corroborated with platform evidence, not from the event alone.

## What we did

- Applied `policy.yaml`: *"audit outbound TCP to port 8080"*
- Connected successfully (baseline)
- Inserted a firewall DROP rule on the client→server path (simulating a
  default-deny NetworkPolicy)
- Repeated the exact same connect — which timed out at the client

## What we observed

| Attempt | Outcome | Event recorded? |
|---|---|---|
| Baseline connect | Succeeded | Yes — src/dst/port/process |
| Same connect under the DROP rule | **Timed out — denied** | **Yes — identical record** |

Both events are byte-for-byte the same shape: the attempt lands in the
stream at SYN-send; the refusal/drop happens afterwards and does not
erase it.

## Why this is valuable — and what it can't tell you

- **Valuable**: a denied exfiltration or lateral-movement attempt still
  leaves forensic evidence — who tried, where to, when. The platform
  silently dropping the packet does not hide the attempt.
- **Limit**: the event's result field reads the same for success and
  denial, so "did it get through" needs the OpenShift network audit logs
  or flow logs alongside. Qualys = attempt telemetry; platform logs =
  verdict telemetry. Together they answer both questions.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
|---|---|---|---|
| S1 | Source + target namespaces | docker | `citi-cli` client + `citi-srv` HTTP service on `citi-net` |
| S2 | Target service with default-deny NetworkPolicy | **NOT COVERED live** | docker has no NetworkPolicy — simulated with an iptables DROP (RESULT S2) |
| S3 | Temporary allow policy for baseline | docker (no policy) | baseline connect succeeds |
| S4 | Qualys network monitoring enabled | `policy.yaml` | egress audit :8080 |
| S5 | OpenShift network evidence for corroboration | **NOT COVERED live** | platform leg |
| E1 | Connect while allowed | **YES** | `tcp_connect` event (client rc=0) |
| E2 | Apply default-deny (iptables DROP) | **YES** (sim) | DROP rule on FORWARD |
| E3 | Repeat the connection | **YES** | client rc=1 (blocked) but `tcp_connect` **still recorded** |
| E4 | Compare successful vs blocked telemetry | **YES** | events are **identical** — attempt recorded, outcome not |
| E5 | Attempt / success / no event? | **YES** | Qualys reports the attempt (H06/H07 pattern confirmed) |

**Not covered live:** S2/S5 (real NetworkPolicy + OpenShift logs — cluster/platform).

## eBPF-Agent events observed (2026-11-03 run)

```json
{"process_kprobe": {"policy_name": "citi-h07-netpol-denied-v2-egress-audit", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/wget", "docker": "ab39fd3a52e2"},
 "args": [{"sock_arg": {"daddr": "172.22.0.2", "dport": 8080, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}]}}
// identical event for the allow baseline AND the iptables-DROPPED attempt
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | egress audit on the service port |
| `pod.yaml` | client ns + target ns + allow NetworkPolicy + default-deny NetworkPolicy to swap |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
# baseline
docker exec citi-client sh -c 'wget -q -T 3 -O /dev/null http://citi-srv:8080'

# simulate the deny
iptables -I DOCKER-USER -s 172.19.0.3 -d 172.19.0.2 -p tcp --dport 8080 -j DROP
docker exec citi-client sh -c 'wget -q -T 3 -O /dev/null http://citi-srv:8080'
# -> "download timed out" client-side, event still recorded

iptables -D DOCKER-USER -s 172.19.0.3 -d 172.19.0.2 -p tcp --dport 8080 -j DROP
```
