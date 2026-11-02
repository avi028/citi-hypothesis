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
