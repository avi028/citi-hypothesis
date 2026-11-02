# QCS-H18 — Process, File, and Network Event Correlation

## What we wanted to prove

Can Qualys reconstruct a full investigation sequence from separate runtime
signals — shell → script creation → script execution → file read → DNS →
network connection — rather than showing isolated events?

## Verdict

**Supported at the sensor level.** The runtime sensor emits every leg of
the chain as events that **join cleanly** (exec_id/parent_exec_id +
container id + unique marker) into the exact sequence the hypothesis asks
for: `bash → create payload+script → script exec → cat reads payload →
getent DNS (UDP :53) → tcp_connect to :8080`. Whether the *platform UI*
offers a pre-joined investigation view is a Qualys product question — the
data to reconstruct it is complete.

## What we did

- Policy: v2 process rule on the chain script + file-open rule on the
  payload + egress rule on :8080; raw `tracingpolicy-dns.yaml` (ip_output,
  UDP DPort 53) for the DNS leg
- Workload: one container ran `bash` → created payload + script → script
  read the payload → `getent hosts citi-h18-test.invalid` (DNS) → bash
  `/dev/tcp` connect to the internal endpoint on :8080

## What we observed (correlated chain)

| Leg | Event | Attribution |
|---|---|---|
| parent shell | `process_exec /usr/bin/bash` | container id |
| script creation | `security_file_open` (payload/script) | bash |
| script execution | `security_bprm_check` (chain-exec) | script matched |
| file read | `security_file_open` (payload) | cat (child of script) |
| DNS | `ip_output` DPort 53, UDP | getent (16 datagrams, retries) |
| network connect | `tcp_connect` 172.17.0.1:8080 | the chain script |
| unique marker | `CITI-H18-9933` in names/argv | all legs |

Join key: exec_id → parent_exec_id across the events, plus the marker
searchable in argv — the full sequence reconstructs in order.

## Caveats

- The DNS leg requires the raw `ip_output` TracingPolicy (UDP is invisible
  to tcp_connect) — same fallback as H06.
- Events are joined by reconstruction (IDs/markers), not by a single
  "investigation" event — that UX is a platform concern.
- v1 cannot express the process-exec leg (script launch marker only via
  file-open).

## Files in this lab

| File | Purpose |
|---|---|
| `policy.yaml` | v2 process + file + network rules for the chain |
| `tracingpolicy-dns.yaml` | raw DNS (UDP :53) leg |
| `policy-v1.yaml` | v1 file + network legs |
| `pod.yaml` | workload running the full chain |
| `RESULT.md` | this document |

## docker run command used for the local proof

```bash
./tetra tracingpolicy add citi-hypothesis/QCS-H18-signal-correlation/policy.yaml
./tetra tracingpolicy add citi-hypothesis/QCS-H18-signal-correlation/tracingpolicy-dns.yaml
docker run --rm debian:stable-slim bash -c '
  MARKER="CITI-H18-9933"
  echo "payload-$MARKER" > /tmp/citi-h18-payload.txt
  cat > /tmp/citi-h18-chain.sh <<SH
#!/bin/bash
cat /tmp/citi-h18-payload.txt
getent hosts citi-h18-test.invalid
exec 3<>/dev/tcp/172.17.0.1/8080
SH
  chmod +x /tmp/citi-h18-chain.sh; /tmp/citi-h18-chain.sh'
```

Result: complete chain reconstructed from events (exec → file → DNS →
connect), all legs attributed to the same container.