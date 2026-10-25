# gatekeep

A stateful L3–L7 firewall for Linux, written in C++17. The kernel (nftables) handles packet forwarding. A userspace engine reached over **NFQUEUE** decides each new connection using L3/L4 rules, per-source rate limits, and the domain the connection is going to, which it reads from the TLS ClientHello (SNI), the HTTP Host header, or the DNS query.

The core design choice is a **slow path / fast path split**. Only the first few packets of each connection go to the engine. Once it decides, the verdict is cached on the kernel's conntrack entry, and the rest of the connection never leaves the kernel.

```
                         ┌───────────────────────── kernel (nftables, forward hook) ─────────────────────────┐
 client ── packet ──►    │ banned src? ─► drop        verdict cached on connection? ─► accept / drop / reset │ ──► server
                         │                                      │ no                                         │
                         │                                      ▼                                            │
                         │                              queue num 0 (NFQUEUE)                                │
                         └──────────────────────────────────────┼────────────────────▲───────────────────────┘
                                                                │ first packets      │ NF_REPEAT + mark
                                                                ▼                    │ (cache it on the flow)
                         ┌──────────────────────────── gatekeep engine (C++) ─────────┴───────────────────────┐
                         │ parse IPv4/TCP/UDP ─► rate limit ─► rules (first match) ─► L7: SNI / Host / DNS    │
                         │ REST API: rules, domains, bans, stats, Prometheus metrics                          │
                         └────────────────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Stateful.** Built on kernel connection tracking. Replies to allowed connections are accepted automatically, and every verdict is cached per connection.
- **Rules.** First match wins, with default deny. Rules match on protocol, source/destination CIDR and destination port ranges. Actions are `allow`, `drop`, or `reject` (TCP RST or ICMP prohibited).
- **Domain blocking by inspecting content.** TLS is recognised by its bytes, not by port 443, so a blocked domain on port 8443 is still caught. Matching includes subdomains (`evil.test` also blocks `cdn.evil.test`). DNS queries are checked one at a time.
- **SYN-flood defence.** Each source IP gets a token-bucket limit on new connections. A source that keeps exceeding it is banned through an nftables set with a timeout, so the kernel drops its packets before they reach userspace and its existing connections are cut.
- **Fails closed.** If the engine is down, or its queue overflows, or its flow table fills up, packets are dropped, not let through unchecked.
- **Hot changes.** Rules and domains can be changed at runtime through the REST API. Conntrack is flushed afterwards, so existing connections are re-checked as well as new ones.
- **Observability.** One JSON log line per decision, `/events`, `/stats`, and Prometheus `/metrics`.

## Benchmark

Measured on Docker Desktop (Apple Silicon, LinuxKit kernel 6.12) with `./scripts/bench.sh`, client → firewall → server:

| mode | 64-byte packets/s (4 UDP streams) | vs kernel only | bulk TCP | engine CPU during TCP |
|---|---:|---:|---:|---:|
| kernel only (engine bypassed) | 1,445k | 100% | 92.3 Gbit/s | – |
| **gatekeep, fast path** | **1,376k** | **95%** | **91.8 Gbit/s** | **~0%** |
| gatekeep, every packet to userspace | 180k | 12% | 92.8 Gbit/s | 80% |

The fast path keeps **95% of raw kernel forwarding rate** and forwards **7.6x more small packets** than sending every packet through userspace. With every packet going to userspace, the engine uses 80% of a core and becomes the bottleneck. With the fast path, it does almost nothing after each connection's first few packets. (Engine CPU is the firewall container's processes. The kernel's own forwarding work isn't charged to the container.)

Bulk TCP is about the same in every mode, because the kernel batches TCP segments into 64 KB GSO super-packets, so even the every-packet mode only makes a few hundred thousand userspace round trips a second. Engine CPU and small-packet rate are where the fast path matters.

## Run it

Needs Docker. Everything runs in three containers: `client` (10.10.1.10), `firewall` (the router between two networks), and `server` (10.10.2.10, running web, HTTPS, DNS and iperf3).

```bash
docker compose up -d --build   # builds the engine and runs its unit tests during the build
./scripts/demo.sh              # 17 checks: rules, SNI/Host/DNS blocking, hot reload, SYN flood ban, fast path
./scripts/bench.sh             # the benchmark above
docker compose logs -f firewall
```

Demo output:

```
1. L3/L4 rules (first match wins, default deny)
  PASS  HTTP to the web server (allow-web)                         allow
  PASS  telnet :23 gets a TCP RST (reject-telnet)                  block
  PASS  quarantined source 10.10.1.66 (quarantine-host)            block
  ...
2. L7 inspection: domains, found by reading the traffic
  PASS  TLS to evil.test (SNI blocked)                             block
  PASS  TLS to cdn.evil.test on port 8443 (TLS found by bytes, not port) block
  PASS  HTTP with Host: tracker.test (Host header blocked)         block
  PASS  DNS query for ads.tracker.test (subdomain of a blocked domain) block
  ...
4. SYN flood -> rate limit -> automatic ban
  PASS  flooding source is banned (kernel @banned set)             block
  ...
5. Fast path: a 3-second bulk transfer, then where its packets went
  iperf3: 92.1 Gbit/s through the firewall
    1444112 packets handled in the kernel (fast path)
          6 packets sent to the engine (slow path): the first few of each connection

17 passed, 0 failed
```

A log line per decision:

```json
{"app":"tls","dst":"10.10.2.10","dst_port":8443,"host":"cdn.evil.test","proto":"tcp","reason":"domain_blocked","rule":"allow-web","src":"10.10.1.10","src_port":47544,"ts":"2026-10-25T05:32:00.084Z","verdict":"reject_flow"}
```

## Control API

Served on `127.0.0.1:8080`.

| Method | Path | |
|---|---|---|
| GET / PUT | `/policy` | Whole policy as JSON (PUT replaces and validates it) |
| POST | `/policy/reload` | Re-read `config/policy.json` |
| POST | `/rules?position=N` | Insert a rule (default: at the bottom) |
| DELETE | `/rules/{id}` | Remove a rule |
| POST / DELETE | `/domains`, `/domains/{name}` | Edit the blocked domain list |
| GET / DELETE | `/bans`, `/bans/{ip}` | Show or lift rate-limit bans |
| GET / PUT | `/config` | `{"fast_path": false}` sends every packet through the engine (for benchmarking) |
| GET | `/flows`, `/events`, `/stats`, `/metrics` | Pending flows, recent decisions, counters, Prometheus metrics |

```bash
curl -X POST 'localhost:8080/rules?position=0' \
     -d '{"id":"maintenance","action":"reject","proto":"tcp","dst_ports":"80"}'
```

Policies are validated strictly. Unknown keys are errors, so a typo like `"dport"` is rejected rather than silently matching everything.

## Layout

```
engine/src/
  main.cpp        wiring: load policy, start API + GC threads, run the queue loop
  nfq.cpp         NFQUEUE receive loop, verdicts back to the kernel (NF_REPEAT + mark)
  packet.cpp      IPv4 / TCP / UDP header parsing
  inspect.cpp     TLS ClientHello SNI, HTTP Host, DNS query parsing
  rules.cpp       rules, CIDRs, port ranges, policy JSON
  ratelimit.hpp   token bucket per source IP
  engine.cpp      the decision logic: new flows, pending inspection, bans, stats
  api.cpp         REST control plane (cpp-httplib)
  kernel.cpp      nft / conntrack side effects (bans, flushes)
engine/tests/     unit tests (parsers, rules, engine), run during the Docker build
nft/gatekeep.nft  kernel ruleset: fast path, verdict marks, the queue
config/policy.json
docker/, docker-compose.yml, scripts/
```

## Limitations

- IPv4 only.
- The engine is one thread on one queue. The next step is `queue num 0-3 fanout` with a thread per queue, flows spread by hash.
- Only the first TCP payload segment is inspected. A ClientHello split so that the SNI lands in the second segment is not reassembled, and the flow is let through.
- Encrypted Client Hello (ECH) hides the SNI. DNS over HTTPS hides the DNS query.
- `reject` resets the client only. The server keeps a half-open connection until it times out ("reset-both" would fix that).
- Rate limiting is per source IP, so a flood with spoofed, random source addresses spreads across buckets. That case calls for SYN cookies and a global limit.

[WALKTHROUGH.md](WALKTHROUGH.md) goes through the code and the design decisions in detail.
