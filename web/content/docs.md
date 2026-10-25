## Overview

Gatekeep is a stateful firewall for Linux, written in C++17. It runs on a machine that routes traffic between two networks and decides, connection by connection, what may pass.

Two parts share the work:

- **The kernel** (nftables) sees every packet. If the packet's connection already has a verdict, the kernel applies it on the spot. This is the fast path.
- **The engine** (a C++ process) sees only the first packets of each new connection, delivered through NFQUEUE. It checks the rate limit, the rules and the destination's name, then hands its verdict back to the kernel, which stores it on the connection. This is the slow path.

The engine's work is per connection, not per packet. In the recorded demo, a 3-second transfer of about 1.45 million packets needed the engine for 6 of them.

## The path of a packet

Take a client opening `https://shop.test`. Its packets are forwarded by the firewall, so they enter the `forward` chain in `nft/gatekeep.nft`:

1. **SYN.** The connection has no verdict (its conntrack mark is 0), so the chain queues the packet to the engine. The engine checks the source's rate limit, then the rules: `allow-web` matches. Because there are domains to block and this is TCP, it can't decide yet. It answers "allow this packet" and keeps the connection in its table of flows under inspection.
2. **SYN-ACK.** A reply to a tracked connection. The kernel accepts it on its own (`ct direction reply accept`).
3. **ACK.** Still no verdict, so it goes back to the engine, which lets it through and keeps waiting.
4. **ClientHello.** The first data packet. The engine recognises a TLS handshake by its first byte (`0x16`), walks the ClientHello to the server name extension and reads `shop.test`. It isn't blocked, so the engine answers "allow the connection".
5. **Everything else.** The kernel has stored the verdict as the connection's mark. Each later packet matches `ct mark 0x1 accept` and never leaves the kernel.

Had the name been `evil.test`, step 4 would have answered "reject the connection": the client gets a TCP reset, and any further packet on that connection is rejected by the kernel.

## How verdicts reach the kernel

The engine answers each queued packet with `NF_REPEAT` and a packet mark. Repeat sends the packet through the chain again, where rules turn the mark into an action and, for connection verdicts, copy it onto the connection:

| Mark | Meaning | Kernel action |
|---|---|---|
| 1 | Allow connection | Accept, store on connection |
| 2 | Drop connection | Drop, store on connection |
| 3 | Allow this packet | Accept, keep sending the connection to the engine |
| 4 | Reject connection | TCP reset or ICMP prohibited, store on connection |
| 5 | Reject this packet | Reset or ICMP for this packet only |
| none | Drop this packet | `NF_DROP`, nothing stored, a retry is judged again |

Keeping the meaning of each verdict in the ruleset means the engine needs no conntrack library: it only returns a number.

## What the engine checks

**Rate limit.** Each source IP has a token bucket of new connections (50 per second, bursts of 100 by default). Connections over the limit are dropped without storing anything, so a retry is judged again later. A source refused 200 times is banned: its address goes into an nftables set with a 30-second timeout, the kernel drops its packets before they reach the engine, and its open connections are deleted.

**Rules.** Read top to bottom, first match wins. A rule can match protocol, source and destination CIDR, and destination port ranges. Actions are `allow`, `drop` and `reject`. Anything no rule matches gets the default action, `drop`.

**Domains.** For an allowed TCP connection, the engine reads the first data packet: the server name of a TLS ClientHello, or the Host header of an HTTP request. TLS is recognised by its bytes, not by port 443. DNS queries to port 53 are checked one by one and never handed to the fast path. A blocked domain also blocks its subdomains.

**Its own limits.** A connection that sends no data within 8 packets is released without inspection. The table of connections under inspection holds at most 65,536 entries; when it's full, new connections that need inspection are dropped.

## Policy file

```json
{
  "default_action": "drop",
  "rules": [
    { "id": "quarantine-host", "action": "drop", "src": "10.10.1.66/32" },
    { "id": "reject-telnet", "action": "reject", "proto": "tcp", "dst_ports": "23" },
    { "id": "allow-dns", "action": "allow", "proto": "udp", "dst": "10.10.2.0/24", "dst_ports": "53" },
    { "id": "allow-web", "action": "allow", "proto": "tcp", "dst": "10.10.2.0/24", "dst_ports": "80,443,8443" },
    { "id": "allow-ping", "action": "allow", "proto": "icmp" }
  ],
  "blocked_domains": ["evil.test", "tracker.test"],
  "rate_limit": { "new_flows_per_sec": 50, "burst": 100, "ban_after": 200, "ban_seconds": 30 },
  "max_inspect_packets": 8
}
```

Validation is strict. An unknown key such as `"dport"` is an error rather than being ignored, because in a firewall a mistyped field silently turns into "match anything".

## Control API

The engine serves a REST API on port 8080.

| Method | Path | What it does |
|---|---|---|
| GET, PUT | `/policy` | Read or replace the whole policy |
| POST | `/policy/reload` | Reload the policy file |
| POST | `/rules?position=N` | Insert a rule, at the bottom by default |
| DELETE | `/rules/{id}` | Remove a rule |
| POST, DELETE | `/domains`, `/domains/{name}` | Add or remove a blocked domain |
| GET, DELETE | `/bans`, `/bans/{ip}` | List or lift bans |
| GET, PUT | `/config` | `{"fast_path": false}` sends every packet to the engine, for benchmarking |
| GET | `/flows` | Connections under inspection |
| GET | `/events` | Recent decisions |
| GET | `/stats`, `/metrics` | Counters, and the same in Prometheus format |

After any policy change the engine flushes the kernel's connection table. Stored verdicts disappear, so open connections are judged again under the new policy, not just new ones.

## Benchmark

From `scripts/bench.sh` on Docker Desktop (Apple Silicon, Linux 6.12), client to firewall to server:

| Mode | 64-byte packets/s | Of kernel alone | Bulk TCP | Engine CPU on TCP |
|---|---|---|---|---|
| Kernel alone (engine bypassed) | 1,445k | 100% | 92.3 Gbit/s | n/a |
| Gatekeep, fast path | 1,376k | 95% | 91.8 Gbit/s | about 0% |
| Every packet to the engine | 180k | 12% | 92.8 Gbit/s | 80% |

Bulk TCP barely changes because the kernel batches TCP into 64 KB segments before queueing, so even the every-packet mode makes few round trips. Small packets and CPU are where the fast path shows.

## Run it

You need Docker. The lab is three containers: a client (`10.10.1.10`), the firewall routing between two networks, and a server (`10.10.2.10`) with web, HTTPS, DNS and iperf3.

```bash
cd firewall
docker compose up -d --build   # builds the engine and runs its unit tests
./scripts/demo.sh              # 17 end-to-end checks
./scripts/bench.sh             # the benchmark
docker compose logs -f firewall
```

The engine logs one JSON line per decision:

```json
{"app":"tls","dst":"10.10.2.10","dst_port":8443,"host":"cdn.evil.test","proto":"tcp","reason":"domain_blocked","rule":"allow-web","src":"10.10.1.10","src_port":47544,"verdict":"reject_flow"}
```

## Limitations

- IPv4 only.
- One engine thread on one queue. The next step is `queue num 0-3 fanout`, with one thread and one flow table per queue.
- Only the first TCP data segment is inspected. A ClientHello split so that the server name falls in the second segment is let through.
- Encrypted Client Hello hides the server name, and DNS over HTTPS hides the query.
- Reject resets the client only; the server keeps a half-open connection until it times out.
- Rate limits are per source address, so a flood from spoofed random addresses spreads across buckets. That case needs SYN cookies and a global limit.
