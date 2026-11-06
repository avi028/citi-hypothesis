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

**Next release:** UDP DNS lookups are not part of TCP connect telemetry —
the DNS leg needs a UDP `ip_output` hook (raw TracingPolicy), which has
been removed from the lab and is slated for a future release.

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
| DNS lookup (UDP) | Not covered — next release |

## Two things to know

- **The connect attempt is always recorded, even if it fails** — the
  event fires when the connection is initiated; success and failure look
  the same on the event (see QCS-H07 for the platform-deny case).
- **DNS is UDP — the TCP connect hook never sees it.** UDP visibility is
  a next-release item (raw `ip_output` hook, removed from this lab).

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| S3 | OpenShift egress controls (only test dest permitted) | **NOT COVERED live** | platform leg (needs OpenShift) |
| E1 | Baseline traffic to approved app dest | **YES** (live) | `tcp_connect` → :8080 |
| E2 | Separate approved test dest | **YES** (live) | `tcp_connect` → :443 (TLS fails; TCP recorded) |
| E3 | DNS resolution then TCP/HTTP | **YES** (partial) | TCP leg recorded; UDP DNS leg = next release |
| E4a | Connection to blocked/unlisted port (:9090) | **YES** (live) | **NO event** — ports outside the policy are invisible (policy-scoped) |
| E4b | Connection to watched port, dropped by firewall | **YES** (live) | client timed out but `tcp_connect` **still recorded** — attempt, not outcome |
| E5 | DNS, dst address, port, process, container attribution | **YES** (partial) | TCP legs carry the tuple + process + container; DNS = next release |

**Not covered live:** S3 (OpenShift egress controls — platform).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | egress audit on approved ports |
| `pod.yaml` | client pod doing the connect cases |
| `RESULT.md` | this document |

`tracingpolicy-dns.yaml` was removed — UDP/DNS visibility is a
next-release item.