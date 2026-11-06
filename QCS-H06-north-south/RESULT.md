# QCS-H06 — Unusual North-South Network Connection

## What we wanted to prove

When a container opens an unexpected outbound connection, can Qualys say
which process made it and where it was going — including when the
destination is unreachable?

## Verdict

**Covered now:** outbound TCP connections to the ports a policy watches
are recorded with full attribution (process, source/destination, port) —
whether the connection succeeds, is refused, or times out. Connections to
ports **not** in the policy are invisible (visibility is policy-scoped).

**Next release:** UDP DNS lookups are not part of TCP connect telemetry.
Agent 1.8 added a native DNS event (`MSG_OP_QUALYS_DNS` — fqdn +
source/destination tuple), but in this build it fires for **host-network
DNS only** — pod-level lookups are not emitted yet. Pod DNS visibility is
a next-release item.

## What we did

- Policy: audit outbound TCP to ports 80/443/8080
- Workload (cluster): resolved a name, connected to an approved port,
  tried a refused port, an unlisted port, and an unreachable address

## What we observed

| Attempt | Recorded? |
| --- | --- |
| Connect to approved port 8080 (success) | Yes — full 5-tuple + process |
| Connect to port 443 — connection refused | Yes — identical record shape |
| Connect to unreachable IP (times out) | Yes — identical record shape |
| Connect to port 9090 — not in the policy list | No — policy-scoped visibility |
| DNS lookup (UDP) | Not covered for pods — host DNS is logged in 1.8; pod DNS next release |

## Two things to know

- **The connect attempt is always recorded, even if it fails** — the
  event fires when the connection is initiated; success and failure look
  the same on the event (see QCS-H07 for the platform-deny case).
- **DNS is UDP — the TCP connect hook never sees it.** Agent 1.8 has a
  native DNS event, but in this build it only reports host-network
  lookups — pod DNS is a next-release item.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| S3 | OpenShift egress controls (only test dest permitted) | **NOT COVERED live** | platform leg (needs OpenShift) |
| E1 | Baseline traffic to approved app dest | **YES** (live) | `tcp_connect` → :8080 |
| E2 | Separate approved test dest | **YES** (live) | `tcp_connect` → :443 (TLS fails; TCP recorded) |
| E3 | DNS resolution then TCP/HTTP | **YES** (partial) | TCP leg recorded; pod DNS = next release (1.8 logs host DNS natively) |
| E4a | Connection to blocked/unlisted port (:9090) | **YES** (live) | **NO event** — ports outside the policy are invisible (policy-scoped) |
| E4b | Connection to watched port, dropped by firewall | **YES** (live) | client timed out but `tcp_connect` **still recorded** — attempt, not outcome |
| E5 | DNS, dst address, port, process, container attribution | **YES** (partial) | TCP legs carry the tuple + process + container; pod DNS = next release |

**Not covered live:** S3 (OpenShift egress controls — platform).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | egress audit on approved ports |
| `pod.yaml` | client pod doing the connect cases |
| `RESULT.md` | this document |

`tracingpolicy-dns.yaml` was removed — agent 1.8 logs host-network DNS
natively (`MSG_OP_QUALYS_DNS`); pod-level DNS visibility is a
next-release item.