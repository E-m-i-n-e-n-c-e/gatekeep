# gatekeep: walkthrough

This explains how the firewall works, file by file, and why it is built this way. Read it alongside the code. The last section has interview questions with answers.

---

## 1. The big picture in one paragraph

Linux already has a very fast packet filter in the kernel (netfilter, configured with `nft`). It's fast because it's dumb: it matches header fields. We want smarter decisions (rate limits, reading the TLS SNI, the HTTP Host header, DNS names) and we want to write them in normal C++. So we split the work:

- **The kernel does the per-packet work.** Every packet of an already-decided connection is handled entirely in the kernel. This is the **fast path**.
- **Userspace does the per-connection work.** The first packets of a new connection are copied to our C++ engine through **NFQUEUE**. The engine decides and tells the kernel, and the kernel **caches the decision on the connection** (its conntrack mark). This is the **slow path**.

Commercial firewalls work the same way. PAN-OS, for example, has a slow path for session setup and policy lookup and a fast path for established sessions. Suricata's NFQ "repeat mode" is the open-source version of this mechanism.

---

## 2. A packet's journey

The client runs `curl -k https://shop.test` (10.10.1.10 → 10.10.2.10:443). The client's route to 10.10.2.0/24 goes through the firewall container, so the firewall's kernel **forwards** these packets, and they hit the `forward` chain in `nft/gatekeep.nft`.

### Packet 1: SYN

1. `ct state invalid`? No. `ip saddr @banned`? No.
2. `ct mark 0x1/0x2/0x4`? No. This is a brand-new connection, so the mark is 0.
3. `ct direction reply`? No, it's in the original direction.
4. `meta mark 0x1..0x5`? No, the packet mark is 0.
5. `queue num 0` sends it to userspace.

In userspace, `nfq.cpp` `on_packet()` → `main.cpp` lambda → `parse_ipv4()` → `Engine::decide()`:

- Is it in the `pending_` table? No, so it's a new flow and goes to `decide_new()`.
- Banned? No. Rate limit: `limiter_.check()` takes a token from 10.10.1.10's bucket. Allowed.
- Rules: `policy_.match(p)` goes through the rules top to bottom. `allow-web` matches (tcp, dst 10.10.2.0/24, port 443).
- It's allowed, but there are blocked domains and this is TCP, so we can't decide yet. The SNI is in the ClientHello, which hasn't arrived. We add the flow to `pending_` and return **`AllowPacket`** (mark 3).

`on_packet()` calls `nfq_set_verdict2(..., NF_REPEAT, mark=3)`. **NF_REPEAT** means "run this packet through the chain again". This time `meta mark 0x3 accept` matches and the SYN goes to the server.

### Packet 2: SYN-ACK (server → client)

`ct direction reply accept`. Replies to a connection we're tracking are accepted in the kernel, so the engine never sees them.

### Packet 3: ACK (client → server, no payload)

It gets queued again, because the connection still has no ct mark. `decide()` finds it in `pending_` and calls `decide_pending()`. There's no payload, so it returns `AllowPacket` and keeps waiting.

### Packet 4: TLS ClientHello

It gets queued. `decide_pending()` sees a payload, so it calls `inspect_tcp_payload()`. The first byte is `0x16` (TLS handshake), so `tls_sni()` runs and returns `shop.test`. `domain_blocked("shop.test")` is false, so `release()` removes the flow from `pending_` and returns **`AllowFlow`** (mark 1).

Back in the kernel, with NF_REPEAT and mark 1, `meta mark 0x1 ct mark set 0x1 accept` sets the **connection's** mark to 1.

### Packets 5 to N: the download

`ct mark 0x1 accept`. That's the fast path. The engine never sees them. In the demo, a 3-second transfer is about 1.4 million packets, and the engine sees 6 of them.

### If the SNI had been `evil.test`

`decide_pending()` returns **`RejectFlow`** (mark 4). The kernel sets ct mark 4 and jumps to `reject_it`, which sends a TCP RST to the client. Any further packet on that connection hits `ct mark 0x4` and is rejected in the kernel.

---

## 3. The files

### `nft/gatekeep.nft`: the kernel half

- `policy drop` on the chain: anything not explicitly accepted is dropped.
- The `queue` has no `bypass` flag. If no process is listening on queue 0, the kernel drops the packets. That makes it **fail closed**: a crashed firewall blocks traffic instead of letting it through.
- `set banned { flags timeout }`: the engine adds an IP with `timeout 30s`, and the kernel removes it automatically when that expires.
- It replaces only `table inet gatekeep` and never runs `flush ruleset`, because Docker keeps its own rules in the same network namespace (for container DNS).
- `counter` on the rules gives live packet counts (`nft list chain inet gatekeep forward`), which the demo uses to show the fast/slow split.

### `engine/src/packet.cpp`: header parsing

The bytes from NFQUEUE start at the IPv4 header:

```
byte 0      version (high 4 bits) = 4, IHL (low 4 bits) = header length in 32-bit words
bytes 2-3   total length
bytes 6-7   flags + fragment offset (low 13 bits)
byte 9      protocol: 6 = TCP, 17 = UDP, 1 = ICMP
bytes 12-15 source IP, 16-19 destination IP
```

So `ihl = (d[0] & 0x0f) * 4`, and the TCP/UDP header starts at `d + ihl`.

```
TCP: bytes 0-1 src port, 2-3 dst port, byte 12 high 4 bits = data offset (header length in words), byte 13 = flags
UDP: bytes 0-1 src port, 2-3 dst port, header is always 8 bytes
```

Things to be ready to explain:
- **Byte order.** Network data is big-endian. `read_u16(p)` is `(p[0] << 8) | p[1]`. This assembles the number the same way on any CPU, so it needs no `ntohs()` and has no alignment problems from casting a pointer to `uint16_t*`.
- **Every length is checked before it's used**: `ihl > len`, `data_offset > l4_len`, and so on. A hostile packet with `IHL = 15` or `data offset = 15` would otherwise make us read past the buffer. Parsers of network input are classic sources of security bugs.
- **Truncation.** We ask the kernel to copy only 4 KB per packet (`kCopyBytes`), so `len` can be smaller than the IP total length. We parse `min(total_len, len)`.
- **Fragments.** A non-first fragment has no TCP/UDP header. Conntrack reassembles fragments before the forward hook, so one showing up here is suspicious, and we reject it.

### `engine/src/inspect.cpp`: reading the application layer

**TLS ClientHello** (`tls_sni`):

```
record:    type 0x16 (handshake) | version 0x03 0x0? | length (2)
handshake: type 0x01 (ClientHello) | length (3)
body:      version (2) | random (32) | session_id_len (1) + id | cipher_suites_len (2) + list
           | compression_len (1) + list | extensions_len (2) | extensions...
extension: type (2) | length (2) | data
SNI (type 0): list_len (2) | name_type (1) = 0 | name_len (2) | name
```

`Reader` is a tiny bounds-checked cursor. Every `u8`/`u16`/`skip` returns false instead of running off the end. The parser skips the fields it doesn't care about using the lengths in the packet, then walks the extensions until it finds type 0.

Why it is safe on truncated input: modern ClientHellos can be over 1,500 bytes (post-quantum key shares), so they can be split across two TCP segments. We only see the first segment. If the SNI extension is complete in it (it usually is, because SNI comes early), we find it. If not, we return "" and let the flow through. That is a known limitation (see below).

**HTTP** (`http_host`): checks that the payload starts with a method (`GET `, `POST `, ...), finds `\r\nHost:` case-insensitively, then strips spaces and `:port`.

**DNS** (`dns_query_name`): the header is 12 bytes, the QR bit (byte 2, top bit) must be 0 (a query), and `qdcount` must be at least 1. The name is a series of length-prefixed labels: `3www4evil4test0` → `www.evil.test`. A length byte over 63 means a compression pointer (`0xC0`), which isn't valid in a question, so it's rejected.

**`domain_matches`**: an exact match, or a match ending in `"." + domain`. `notevil.test` must *not* match `evil.test`; that's why it checks for the dot.

### `engine/src/rules.cpp`: policy

- `Cidr`: `mask = 0xffffffff << (32 - prefix)`, and `contains(ip)` is `(ip & mask) == network`. The special case `prefix == 0` exists because shifting a 32-bit value by 32 is **undefined behaviour** in C++.
- The rule list is a `std::vector`, checked in order with first match winning. That's O(rules) per new flow, which is fine for tens or hundreds of rules. PAN-OS and nftables compile big rule sets into lookup structures (tries for CIDRs, hash sets for ports). Mention this as a scaling step.
- Strict JSON: unknown keys are errors. A firewall rule with a typo (`dport` instead of `dst_ports`) silently becomes "any port". In a firewall, that turns a block rule into a block-everything rule, or worse, an allow-everything rule.

### `engine/src/ratelimit.hpp`: token bucket

Each source IP has a bucket of `burst` tokens that refills at `rate` tokens per second. A new flow costs one token. The bucket allows short bursts (a browser opening 20 connections) but caps the sustained rate. Refill is computed lazily from elapsed time when a token is taken, so no timer is needed. After `ban_after` refusals, the source is banned.

### `engine/src/engine.cpp`: decisions

- `decide()` takes the mutex, looks up the 5-tuple in `pending_`, and calls either `decide_new()` or `decide_pending()`.
- `pending_` only holds flows still being inspected. Decided flows live only in the kernel, so the engine's memory doesn't grow with the number of connections.
- `kMaxPending` caps it. An attacker can open lots of connections that never send data. When the table is full, new flows that need inspection are dropped (fail closed).
- `max_inspect_packets`: a flow that never sends data (or sends it after 8 packets) is released with `inspect_limit`.
- DNS (UDP/53) is never offloaded (`per_packet`). One UDP "connection" (the same 5-tuple) can carry many queries, and we want to check every one of them.

### `engine/src/nfq.cpp`: talking to the kernel

- `nfq_create_queue(h, 0, on_packet, ...)` binds queue 0. Then it's a loop of `recv()` → `nfq_handle_packet()`, which calls `on_packet` for each packet.
- `NFQNL_COPY_PACKET, 4096`: copy the first 4 KB of each packet to userspace.
- `NFQA_CFG_F_GSO`: accept GSO "super-packets" (up to 64 KB of TCP batched by the kernel) as they are, instead of forcing the kernel to split them first.
- `ENOBUFS`: we fell behind and the kernel's socket buffer overflowed. Those packets are dropped (fail closed), and we keep going.
- Verdicts: `NF_DROP`, or `NF_REPEAT` plus a mark. We never use `NF_ACCEPT`. Repeating with a mark lets the *nftables rules* own what each verdict means (accept, reset, cache it on the connection), so the engine doesn't need libnetfilter_conntrack.

### `engine/src/api.cpp` and `kernel.cpp`: control plane

- `cpp-httplib` (a header-only HTTP server) runs on its own thread.
- After every policy change, `conntrack -F` flushes the connection table. That deletes the cached ct marks, so **existing** connections come back to the engine and get judged against the new rules. Without it, a new "block port 80" rule would only affect new connections.
- `kernel.cpp` runs `nft` and `conntrack` with `posix_spawnp` and an argument vector. There's no shell, so there's no way to inject a command, even though the IP strings come from our own code anyway.

### `main.cpp`

It loads the policy, starts the API thread and a GC thread (which expires pending flows, bans and idle buckets every 5 seconds), flushes stale conntrack state from a previous run, and runs the queue loop on the main thread.

### Threads and locking

There are three threads: the packet loop, the API, and GC. One `std::mutex` protects all engine state. The packet loop holds it only for the length of one decision (microseconds). It's simple and correct. With multiple queues you would shard state per queue instead (see scaling).

---

## 4. Things discovered while building it (good interview stories)

1. **A dropped first packet can't cache a verdict.** Conntrack only *confirms* (inserts) a connection when a packet makes it out of the box. If we drop the SYN, the conntrack entry is thrown away along with its mark, so the client's SYN retransmits come back to the engine. That is correct, and it's also a strength: **denied SYN floods can't fill the conntrack table.**
2. **GSO hides per-packet cost.** In bulk TCP, sending every packet to userspace barely reduced throughput, because the kernel batches TCP into 64 KB super-packets, so "every packet" was only about 270k round trips per second. The fast path still made a big difference to CPU (see the benchmark), and on small packets, where per-packet cost dominates.
3. **Half-open connections on reject.** `reject with tcp reset` sends the RST only to the client. When the ClientHello was blocked, the server was left waiting. The lab's Python HTTPS server ran the TLS handshake inside `accept()`, so a single blocked connection froze the whole server. PAN-OS has a "reset-both" action for this reason.
4. **`nft reset counters` only resets named counters, not per-rule ones** (on Debian 12's nft 1.0.6). The demo measures before/after differences instead.

---

## 5. Scaling it further

- **Multiple queues:** `queue num 0-3 fanout` hashes flows across 4 queues, with one engine thread per queue and a per-thread flow table, so no shared lock on the hot path.
- **XDP/eBPF:** drop banned IPs in the NIC driver, before the kernel even allocates a packet buffer. That's the cheapest possible drop, for volumetric floods.
- **Rule lookup:** compile rules into a decision tree or tries, so cost doesn't grow linearly with the number of rules.
- **TCP reassembly** for ClientHellos split across segments.
- **IPv6**: the same design, with a different header parser (and extension headers to walk).

---

## 6. Interview questions

**Q: Why not do everything in userspace?**
Copying every packet to userspace and back costs a context switch and a copy per packet. In the benchmark, small-packet throughput was 180k packets/s with every packet going to userspace versus 1.38M with the fast path (7.6x), and the engine used 80% of a core on a TCP stream versus about 0%. Most packets of a connection need no new decision, so only the first few should pay that cost.

**Q: Why not do everything in nftables?**
nftables matches header fields. It can't parse a TLS ClientHello's extension list or decode DNS labels. You'd want those decisions in a normal language, with tests.

**Q: What does NFQUEUE do?**
It's a netfilter verdict target. The kernel parks the packet, sends a copy to a userspace process over a netlink socket, and waits for a verdict (accept, drop or repeat, optionally with a new mark). The packet stays in the kernel. Userspace only returns a decision.

**Q: What is conntrack and what is a ct mark?**
Conntrack is the kernel's connection table: every flow (5-tuple plus state such as NEW or ESTABLISHED) has an entry. A ct mark is a 32-bit value stored on that entry. Every packet of the connection, in both directions, can read it. We store our verdict there, which is what makes the fast path possible.

**Q: Why NF_REPEAT instead of NF_ACCEPT?**
NF_ACCEPT would let the packet through, but nothing would remember the decision. With NF_REPEAT and a mark, the packet goes through our chain again, and an nftables rule copies the packet mark onto the connection's mark and applies the action. That keeps "what a verdict means" in one readable ruleset.

**Q: What happens if the engine crashes?**
The queue has no `bypass`, so the kernel drops packets for queue 0 while nobody is listening. That's fail closed. Already-allowed connections keep working, because their verdict lives in the kernel. Docker would restart the container, and the engine flushes conntrack on startup.

**Q: Fail open or fail closed?**
Closed, because it's a security device: an outage is better than letting attacks through unchecked. Some deployments choose fail open for availability. nftables has `queue ... bypass` for that, and NFQUEUE has a fail-open flag.

**Q: How do you find the SNI?**
Parse the TLS record header, then the handshake header, skip the fixed-size fields of the ClientHello, skip the variable-length fields using their length prefixes, then walk the extensions until you reach type 0 (server_name). Every read is bounds-checked.

**Q: Can this be bypassed?**
Yes, in known ways:
- **ECH** encrypts the SNI.
- **DNS-over-HTTPS** hides DNS queries.
- **A ClientHello split** so that the SNI is in the second TCP segment.
- **Domain fronting**: the SNI says one thing and the HTTP Host header inside TLS says another.
- **Direct IP connections**, which use no name at all.

Real next-generation firewalls answer these with TLS decryption, App-ID signatures and IP reputation feeds.

**Q: How do you stop a SYN flood?**
Here: a per-source token bucket on new flows, then an automatic ban through an nftables set, so the kernel drops the source's packets before they reach userspace. Denied SYNs don't create conntrack entries. For spoofed, random-source floods, per-IP limits don't help. You'd add SYN cookies (the kernel answers without storing state), a global new-connection rate limit, or XDP filtering.

**Q: What is a token bucket?**
A bucket holds up to B tokens and gains R tokens per second. Each event costs one token, and if the bucket is empty the event is refused. It allows bursts of up to B while capping the long-run rate at R.

**Q: How does a policy change affect existing connections?**
Their verdicts are cached in conntrack, so after every change we flush conntrack. Each existing connection's next packet becomes "new" again (Linux's loose TCP tracking picks up mid-stream connections), goes to the engine, and is judged under the new rules.

**Q: Why is the engine's memory bounded?**
Decided connections are stored only in the kernel. The engine keeps only flows that are still being inspected, capped at 65,536, plus rate-limit state per source, cleared after 60 seconds idle.

**Q: Why parse with `read_u16(p)` instead of casting to a struct?**
Casting a byte pointer to `struct tcphdr*` can be misaligned, and strictly speaking it breaks C++ aliasing rules. Explicit byte reads are portable, handle endianness, and make every bounds check visible.

**Q: What is `std::optional` doing in `Rule`?**
`src` and `dst` are optional: no CIDR means "any address". `std::optional<Cidr>` makes that explicit, instead of using a magic value like 0.0.0.0/0.

**Q: How would you make it multi-core?**
Use `queue num 0-3 fanout`. The kernel hashes each flow to one queue, so all packets of a connection reach the same thread. Each thread then has its own flow table and rate limiters, with no shared lock on the hot path.

**Q: How did you test it?**
- **Unit tests** (92 checks) build raw packets byte by byte, including ClientHellos, DNS queries and truncated or malformed inputs. They exercise the parsers, rule matching and the full decision engine without a kernel. They run inside the Docker build, so a failing test means no image.
- **An end-to-end demo** (17 checks) uses real traffic: curl, dig, nc, ping, hping3 and iperf3 across three containers.

**Q: What would you add next?**
Multi-queue fanout, reset-both, TCP reassembly for split ClientHellos, IPv6, and moving ban-list drops to XDP.
