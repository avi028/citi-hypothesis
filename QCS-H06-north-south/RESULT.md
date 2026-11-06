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

**Also covered (agent 1.8):** DNS lookups to external resolvers are
logged natively — `MSG_OP_QUALYS_DNS` carries the fqdn, answers, and the
**pod's own source IP** (verified live: this pod's `example.com`
resolution was recorded). The remaining gap is **cluster-internal DNS**
(lookups served by the kube-dns service) — not emitted in this build;
that leg is a next-release item.

## What we did

- Policy: audit outbound TCP to ports 80/443/8080
- Workload (cluster): resolved `example.com`, connected to it on :80 and
  :443, attempted :9090 (outside the policy list), and connected to an
  **unreachable IP** on a watched port — real north-south (external)
  traffic

## What we observed

| Attempt | Recorded? |
| --- | --- |
| Connect to `example.com:80` (external, success) | Yes — full 5-tuple + process (`curl`) |
| Connect to `example.com:443` (external, TLS) | Yes — identical record shape |
| Connect to port 9090 — not in the policy list | No — policy-scoped visibility |
| Connect to unreachable IP `10.255.255.1:8080` | **Yes** — the attempt registers an event even though nothing answers |
| DNS lookup of `example.com` (external resolver) | **Yes** — `MSG_OP_QUALYS_DNS` with pod src IP, fqdn + answers |
| DNS lookup served by kube-dns (cluster-internal) | No — not emitted in this build; next release |

## Two things to know

- **The connect attempt is always recorded, even if it fails** — the
  event fires when the connection is initiated; success and failure look
  the same on the event (see QCS-H07 for the platform-deny case).
- **DNS is UDP — the TCP connect hook never sees it.** Agent 1.8's
  native DNS event does cover it for external resolvers (pod src IP +
  fqdn + answers, verified live); only the kube-dns/cluster-internal
  path is still silent — a next-release item.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
| --- | --- | --- | --- |
| S3 | OpenShift egress controls (only test dest permitted) | **NOT COVERED live** | platform leg (needs OpenShift) |
| E1 | Baseline traffic to approved app dest | **YES** (live) | `tcp_connect` → `example.com:80` |
| E2 | Separate approved test dest | **YES** (live) | `tcp_connect` → `example.com:443` (external) |
| E3 | DNS resolution then TCP/HTTP | **YES** (live) | `MSG_OP_QUALYS_DNS` for `example.com` (pod src IP + answers) then `tcp_connect` — both legs recorded |
| E4a | Connection to blocked/unlisted port (:9090) | **YES** (live) | **NO event** — ports outside the policy are invisible (policy-scoped) |
| E4b | Connection to watched port, unreachable/dropped | **YES** (live) | `10.255.255.1:8080` connect timed out but the `Network Activity` event **still recorded** — attempt, not outcome |
| E5 | DNS, dst address, port, process, container attribution | **YES** (live) | TCP legs carry tuple + process + container; the DNS event carries fqdn + answers + pod src IP |

**Not covered live:** S3 (OpenShift egress controls — platform).

## Files in this lab

| File | Purpose |
| --- | --- |
| `policy-v1.yaml` / `policy-v2.yaml` | egress audit on approved ports |
| `pod.yaml` | client pod doing the connect cases |
| `RESULT.md` | this document |

`tracingpolicy-dns.yaml` was removed — agent 1.8 logs DNS natively
(`MSG_OP_QUALYS_DNS`), including pod lookups to external resolvers.
Cluster-internal (kube-dns) DNS remains a next-release item.
EC2 verification (`hypo-run.py --labs 6`, v1 mode, 2026-11-06): **PROVEN** — 11 matching events.
