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
| GET | `/kernel` | nftables counters: fast path, slow path, banned drops |

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

Then start the website and open `http://localhost:3000/live` to drive the lab from the browser:

```bash
cd web && npm install && npm run dev
```

The engine logs one JSON line per decision:

```json
{"app":"tls","dst":"10.10.2.10","dst_port":8443,"host":"cdn.evil.test","proto":"tcp","reason":"domain_blocked","rule":"allow-web","src":"10.10.1.10","src_port":47544,"verdict":"reject_flow"}
```

## Live mode setup

The Live page reaches the control API (port 8080) and the scenario runner (port 8081, in the client container). Both accept browser calls from pages on `localhost` and `127.0.0.1`, and from the origins in `GATEKEEP_CORS_ORIGINS` (by default `https://gatekeep.akhilk.in`). Requests that change something from any other site's page are refused with 403, even ones a browser sends without asking first.

Both also answer Chrome's local-network check, so the hosted site can reach a lab on your own computer: Chrome asks once for permission. Safari blocks an https page from calling `http://127.0.0.1`, so use Chrome.

To point the site at a lab somewhere else, build it with `NEXT_PUBLIC_GATEKEEP_API` and `NEXT_PUBLIC_GATEKEEP_RUNNER` set, and start the lab with that site in `GATEKEEP_CORS_ORIGINS`.

## Limitations

- IPv4 only.
- One engine thread on one queue. The next step is `queue num 0-3 fanout`, with one thread and one flow table per queue.
- Only the first TCP data segment is inspected. A ClientHello split so that the server name falls in the second segment is let through.
- Encrypted Client Hello hides the server name, and DNS over HTTPS hides the query.
- Reject resets the client only; the server keeps a half-open connection until it times out.
- Floods inside an already-allowed connection aren't policed, since its packets take the fast path. A per-source packet-rate `meter` in nftables, above the fast-path rule, would close this.
- Rate limits are per source address, so a flood from spoofed random addresses spreads across buckets. That case needs SYN cookies and a global limit.
