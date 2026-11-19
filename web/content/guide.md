## Overview

Gatekeep is a stateful firewall for Linux, written in C++17. It runs on a machine that routes traffic between two networks and decides, connection by connection, what may pass: rules on addresses and ports, the website a connection is going to, and floods of new connections.

Two parts share the work:

- **The kernel** (nftables) sees every packet. If the packet's connection already has a verdict, the kernel applies it on the spot. This is the fast path.
- **The engine** (a C++ process) sees only the first packets of each new connection. It checks the rate limit, the rules and the destination's name, then hands its verdict back to the kernel, which stores it on the connection. This is the slow path.

The engine decides once per connection; the kernel remembers the decision and enforces it for every later packet of that connection. In the recorded demo, a 3-second transfer of about 1.45 million packets needed the engine for 6 of them.

Two details are easy to get wrong:

- **A verdict belongs to one connection, not to a sender.** A connection is identified by its 5-tuple: source IP, source port, destination IP, destination port, protocol. The same machine's next new connection starts with no verdict and goes to the engine again.
- **The engine never rewrites the policy.** Rules, blocked domains and rate limits change only through the API. What the engine hands the kernel is a verdict for one connection.

## Where it runs

Gatekeep needs a Linux kernel. On a Mac, Docker Desktop provides one: it runs a small Linux virtual machine, and every container runs inside it. The three lab containers share that one kernel, and each gets its own isolated network stack (a network namespace): its own interfaces, addresses, routes and nftables rules.

<figure class="diagram">
<div class="diagram-scroll">
<svg viewBox="0 0 760 250" role="img" aria-label="The client on clientnet routes to servernet through the firewall at 10.10.1.2; the server routes back through 10.10.2.2. The firewall publishes port 8080 and the client publishes port 8081 on the Mac.">
<defs><marker id="dg-a1" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah"/></marker></defs>
<rect x="10" y="20" width="300" height="150" rx="10" class="d-soft"/>
<text x="26" y="42" class="d-small">clientnet 10.10.1.0/24</text>
<rect x="450" y="20" width="300" height="150" rx="10" class="d-soft"/>
<text x="734" y="42" text-anchor="end" class="d-small">servernet 10.10.2.0/24</text>
<rect x="34" y="62" width="170" height="84" rx="8" class="d-box"/>
<text x="119" y="88" text-anchor="middle" class="d-bold">client 10.10.1.10</text>
<text x="119" y="108" text-anchor="middle" class="d-small">curl, dig, nc, hping3, iperf3</text>
<text x="119" y="126" text-anchor="middle" class="d-small">scenario runner :8081</text>
<rect x="290" y="62" width="180" height="84" rx="8" class="d-fast-box"/>
<text x="380" y="88" text-anchor="middle" class="d-bold d-tfast">firewall</text>
<text x="380" y="108" text-anchor="middle" class="d-small">10.10.1.2 | 10.10.2.2</text>
<text x="380" y="126" text-anchor="middle" class="d-small">nftables + engine + API :8080</text>
<rect x="556" y="62" width="170" height="84" rx="8" class="d-box"/>
<text x="641" y="88" text-anchor="middle" class="d-bold">server 10.10.2.10</text>
<text x="641" y="108" text-anchor="middle" class="d-small">web 80, https 443/8443,</text>
<text x="641" y="126" text-anchor="middle" class="d-small">telnet 23, dns 53, iperf3</text>
<line x1="204" y1="96" x2="286" y2="96" class="d-line" marker-end="url(#dg-a1)"/>
<text x="245" y="88" text-anchor="middle" class="d-small">via 10.10.1.2</text>
<line x1="474" y1="96" x2="552" y2="96" class="d-line" marker-end="url(#dg-a1)"/>
<line x1="552" y1="112" x2="474" y2="112" class="d-line" marker-end="url(#dg-a1)"/>
<text x="513" y="132" text-anchor="middle" class="d-small">via 10.10.2.2</text>
<rect x="230" y="196" width="300" height="44" rx="8" class="d-box"/>
<text x="380" y="216" text-anchor="middle" class="d-bold">your computer: 127.0.0.1</text>
<text x="380" y="232" text-anchor="middle" class="d-small">browser, scripts</text>
<line x1="350" y1="194" x2="350" y2="150" class="d-line d-dash" marker-end="url(#dg-a1)"/>
<text x="344" y="178" text-anchor="end" class="d-small">:8080 API</text>
<line x1="260" y1="200" x2="150" y2="150" class="d-line d-dash" marker-end="url(#dg-a1)"/>
<text x="196" y="186" text-anchor="end" class="d-small">:8081 runner</text>
</svg>
</div>
<figcaption>Solid arrows are lab traffic, routed through the firewall. Dashed arrows are the two ports Docker publishes on your computer only.</figcaption>
</figure>

- **client** sends test traffic and runs the scenario runner that the Live page uses.
- **firewall** is the only route between the two networks. It runs the nftables rules and the engine.
- **server** answers allowed traffic: a web server, HTTPS on 443 and 8443, a telnet-like banner on 23, DNS (every `*.test` name resolves to it) and iperf3.

Only traffic **routed through** the firewall container is inspected: in the lab, traffic between the client and the server. Your computer's own traffic never enters these networks, and calls to the firewall's API are addressed *to* it, so they don't cross the forward path. Deployed for real, the same engine and ruleset would run on a Linux gateway, with real interfaces instead of Docker networks.

## The Linux pieces

A program like curl or a web server only sees packets addressed to it. Packets merely passing through a router are handled entirely inside the kernel, so filtering them means getting into the kernel's packet handling. Each piece below exists because the one before it can't do something.

<div class="piece">
<h3>1. netfilter: hook points inside the kernel</h3>
<dl>
<dt>What it is</dt><dd>Fixed points in the kernel's packet-processing code where extra logic can be attached: packet arrived, packet is for this machine, <strong>packet is being forwarded</strong>, packet is leaving.</dd>
<dt>Think of it as</dt><dd>Middleware hooks in a web framework, with packets instead of HTTP requests.</dd>
<dt>Why it's needed</dt><dd>Without it, filtering packets would mean changing the kernel's source code.</dd>
<dt>In Gatekeep</dt><dd>Only the <strong>forward</strong> hook is used: packets passing through.</dd>
</dl>
</div>

<div class="piece">
<h3>2. nftables: rules for those hooks</h3>
<dl>
<dt>What it is</dt><dd>A rule language and a tool, <code>nft</code>, for attaching rules to netfilter's hooks. Rules like <code>tcp dport 23 drop</code> are loaded with <code>nft -f file.nft</code> and evaluated by the kernel for every packet.</dd>
<dt>Think of it as</dt><dd>A declarative config for that middleware, like nginx rules.</dd>
<dt>Why it's needed</dt><dd>It gives a safe, fast rule engine that already lives in the kernel.</dd>
<dt>Its limit</dt><dd>It matches fields at fixed places: addresses, ports, protocol, flags. It can't walk a variable-length structure like a TLS ClientHello to find the website name. <strong>That's why the C++ engine exists.</strong></dd>
<dt>In Gatekeep</dt><dd><code>nft/gatekeep.nft</code>: one chain on the forward hook, <code>policy drop</code>, so anything not explicitly accepted is dropped.</dd>
</dl>
</div>

<div class="piece">
<h3>3. conntrack: the connection table</h3>
<dl>
<dt>What it is</dt><dd>The kernel keeps a table of every connection, keyed by 5-tuple, with its state (new, established) and which side started it.</dd>
<dt>Think of it as</dt><dd>A session store: every packet is looked up and tagged with its session, and whether it's a reply.</dd>
<dt>Why it's needed</dt><dd>Without it every packet is judged with no memory, and a firewall can't tell the server answering an allowed request from a random packet. It's what makes a firewall <strong>stateful</strong>.</dd>
<dt>In Gatekeep</dt><dd><code>ct direction reply accept</code> lets replies through without the engine; <code>ct state invalid drop</code> discards packets that fit no valid connection.</dd>
</dl>
</div>

<div class="piece">
<h3>4. ct mark: a field on each connection</h3>
<dl>
<dt>What it is</dt><dd>A free 32-bit number on every conntrack entry, there for you to set and read.</dd>
<dt>Think of it as</dt><dd>Your own key on the session object: <code>session.verdict = "allow"</code>.</dd>
<dt>Why it's needed</dt><dd>The engine's decision has to live somewhere the kernel can check on every packet without asking anyone. conntrack already finds each packet's connection, so storing the verdict there makes the lookup free.</dd>
<dt>In Gatekeep</dt><dd>1 allowed, 2 dropped, 4 rejected. The rule <code>ct mark 1 accept</code> <em>is</em> the fast path.</dd>
</dl>
</div>

<div class="piece">
<h3>5. NFQUEUE: letting a program decide</h3>
<dl>
<dt>What it is</dt><dd>An nftables action, <code>queue num 0</code>: don't decide here, hand the packet to a program and wait. The kernel parks the packet with an ID and sends a copy to the program, which replies with a verdict for that ID. It's a kernel feature, not a command.</dd>
<dt>Think of it as</dt><dd>A middleware making a blocking call to an external auth service before letting a request continue.</dd>
<dt>Why it's needed</dt><dd>Decisions nftables can't make, like reading the website name, happen in a normal program where any parsing is possible and tests can be written.</dd>
<dt>How it connects</dt><dd>Over a <strong>netlink socket</strong>, the standard channel between the kernel and programs. The engine uses the C library <strong>libnetfilter_queue</strong>: <code>recv()</code> gets the next packet, <code>nfq_set_verdict2()</code> answers it.</dd>
<dt>Its cost</dt><dd>Every queued packet means a copy and a switch into userspace and back. For every packet, that took 80% of a CPU core at 12% of the normal packet rate, which is why only each connection's first few packets take this path.</dd>
<dt>In Gatekeep</dt><dd>The last rule in the chain. There's no <code>bypass</code> flag, so if the engine is down, queued packets are dropped: the firewall fails closed.</dd>
</dl>
</div>

<div class="piece">
<h3>6. NF_REPEAT and the packet mark: storing the answer</h3>
<dl>
<dt>The problem</dt><dd>A plain accept lets the packet through but stores nothing, so the next packet would be queued again.</dd>
<dt>What happens</dt><dd>The engine replies with packet ID, <code>NF_REPEAT</code> and a mark. The kernel sets the <strong>packet mark</strong> (<code>meta mark</code>, metadata on the parked packet that lasts only while it's in this kernel) and runs it through the chain again. The rule <code>meta mark 1 → ct mark set 1, accept</code> copies the decision onto the connection and lets the packet go.</dd>
<dt>Think of it as</dt><dd>The auth service answering "re-run the pipeline with header <code>X-Verdict: allow</code>"; a middleware sees the header and writes it into the session.</dd>
<dt>Why this way</dt><dd>The engine only returns a number, so it needs no conntrack library, and the meaning of each verdict stays readable in the ruleset.</dd>
</dl>
</div>

<div class="piece">
<h3>7. An nftables set: the ban list</h3>
<dl>
<dt>What it is</dt><dd>A hash set of IP addresses inside the kernel that rules can test (<code>ip saddr @banned drop</code>), with an expiry on each entry.</dd>
<dt>Think of it as</dt><dd>A Redis set with a TTL on each member.</dd>
<dt>In Gatekeep</dt><dd>A flooding source is added with <code>timeout 30s</code>; the kernel drops its packets before any other rule runs and removes it after 30 seconds.</dd>
</dl>
</div>

Put together, it's a cache:

<figure class="diagram">
<div class="diagram-scroll">
<svg viewBox="0 0 720 270" role="img" aria-label="At the forward hook the kernel checks the connection's ct mark. A hit applies the stored verdict in the kernel. A miss queues the packet to the engine, whose answer is written back as the connection's ct mark.">
<defs>
<marker id="dg-a2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah"/></marker>
<marker id="dg-a2f" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah-fast"/></marker>
<marker id="dg-a2s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah-slow"/></marker>
</defs>
<rect x="10" y="20" width="170" height="60" rx="8" class="d-box"/>
<text x="95" y="46" text-anchor="middle" class="d-bold">packet arrives</text>
<text x="95" y="64" text-anchor="middle" class="d-small">forward hook</text>
<line x1="180" y1="50" x2="236" y2="50" class="d-line" marker-end="url(#dg-a2)"/>
<rect x="240" y="20" width="220" height="60" rx="8" class="d-box"/>
<text x="350" y="46" text-anchor="middle" class="d-bold">connection has a ct mark?</text>
<text x="350" y="64" text-anchor="middle" class="d-small">conntrack lookup by 5-tuple</text>
<line x1="460" y1="50" x2="526" y2="50" class="d-line-fast" marker-end="url(#dg-a2f)"/>
<text x="493" y="42" text-anchor="middle" class="d-small d-tfast">yes</text>
<rect x="530" y="20" width="180" height="60" rx="8" class="d-fast-box"/>
<text x="620" y="46" text-anchor="middle" class="d-bold d-tfast">apply stored verdict</text>
<text x="620" y="64" text-anchor="middle" class="d-small">cache hit: kernel only</text>
<line x1="350" y1="80" x2="350" y2="126" class="d-line-slow" marker-end="url(#dg-a2s)"/>
<text x="358" y="108" class="d-small d-tslow">no</text>
<rect x="240" y="130" width="220" height="56" rx="8" class="d-slow-box"/>
<text x="350" y="154" text-anchor="middle" class="d-bold d-tslow">queue num 0 → engine</text>
<text x="350" y="172" text-anchor="middle" class="d-small">NFQUEUE over netlink</text>
<line x1="350" y1="186" x2="350" y2="216" class="d-line-slow" marker-end="url(#dg-a2s)"/>
<text x="358" y="206" class="d-small d-tslow">NF_REPEAT + mark 1</text>
<rect x="190" y="220" width="320" height="44" rx="8" class="d-box"/>
<text x="350" y="240" text-anchor="middle" class="d-bold">meta mark 1 → ct mark set 1, accept</text>
<text x="350" y="256" text-anchor="middle" class="d-small">cache fill: once per connection</text>
<path d="M510,242 C620,242 620,120 620,84" class="d-line-fast d-dash" marker-end="url(#dg-a2f)"/>
<text x="628" y="170" class="d-small d-tfast">next packets hit</text>
</svg>
</div>
<figcaption>The kernel keeps a per-connection cache of decisions. A miss calls the engine once; its answer is written back, and every later packet of the connection is a hit.</figcaption>
</figure>

## The path of a packet

The client opens `https://shop.test`. Every packet it sends goes down the forward chain in `nft/gatekeep.nft`, in this order:

| # | Rule | Meaning |
|---|---|---|
| 1 | `ct state invalid → drop` | Fits no valid connection |
| 2 | `ip saddr @banned → drop` | Banned source; checked before the fast path, so a ban overrides allowed connections |
| 3–5 | `ct mark 1 / 2 / 4 → accept / drop / reject` | **Fast path**: the connection already has a verdict |
| 6 | `ct direction reply → accept` | Replies of connections still being inspected |
| 7–11 | `meta mark 1–5 → …` | The engine's answer coming back (NF_REPEAT); 1, 2 and 4 are also stored as the ct mark |
| 12 | `queue num 0` | **Slow path**: ask the engine |

<figure class="diagram">
<div class="diagram-scroll">
<svg viewBox="0 0 760 470" role="img" aria-label="Sequence: the SYN and ACK are queued to the engine and allowed one at a time; the SYN-ACK is accepted by the kernel as a reply; the ClientHello is inspected and the connection allowed with mark 1; every later packet is accepted by the kernel without the engine.">
<defs>
<marker id="dg-a3" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah"/></marker>
<marker id="dg-a3f" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah-fast"/></marker>
<marker id="dg-a3s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah-slow"/></marker>
</defs>
<text x="80" y="24" text-anchor="middle" class="d-bold">client</text>
<text x="300" y="24" text-anchor="middle" class="d-bold">firewall kernel</text>
<text x="480" y="24" text-anchor="middle" class="d-bold d-tslow">engine</text>
<text x="680" y="24" text-anchor="middle" class="d-bold">server</text>
<line x1="80" y1="36" x2="80" y2="460" class="d-line d-dash"/>
<line x1="300" y1="36" x2="300" y2="460" class="d-line d-dash"/>
<line x1="480" y1="36" x2="480" y2="460" class="d-line-slow d-dash"/>
<line x1="680" y1="36" x2="680" y2="460" class="d-line d-dash"/>
<line x1="82" y1="62" x2="296" y2="62" class="d-line" marker-end="url(#dg-a3)"/>
<text x="90" y="56" class="d-bold">1 SYN</text>
<line x1="302" y1="76" x2="476" y2="76" class="d-line-slow" marker-end="url(#dg-a3s)"/>
<text x="390" y="70" text-anchor="middle" class="d-small">no ct mark: queue 0</text>
<line x1="478" y1="96" x2="304" y2="96" class="d-line-slow" marker-end="url(#dg-a3s)"/>
<text x="492" y="100" class="d-small d-tslow">allow-web matches → mark 3</text>
<line x1="302" y1="128" x2="676" y2="128" class="d-line" marker-end="url(#dg-a3)"/>
<line x1="678" y1="160" x2="84" y2="160" class="d-line" marker-end="url(#dg-a3)"/>
<text x="560" y="154" class="d-bold">2 SYN-ACK</text>
<text x="190" y="178" text-anchor="middle" class="d-small">reply: accepted by kernel</text>
<line x1="82" y1="206" x2="296" y2="206" class="d-line" marker-end="url(#dg-a3)"/>
<text x="90" y="200" class="d-bold">3 ACK</text>
<line x1="302" y1="216" x2="476" y2="216" class="d-line-slow" marker-end="url(#dg-a3s)"/>
<line x1="478" y1="232" x2="304" y2="232" class="d-line-slow" marker-end="url(#dg-a3s)"/>
<text x="492" y="236" class="d-small d-tslow">no data yet → mark 3</text>
<line x1="302" y1="258" x2="676" y2="258" class="d-line" marker-end="url(#dg-a3)"/>
<line x1="82" y1="290" x2="296" y2="290" class="d-line" marker-end="url(#dg-a3)"/>
<text x="90" y="284" class="d-bold">4 ClientHello</text>
<line x1="302" y1="300" x2="476" y2="300" class="d-line-slow" marker-end="url(#dg-a3s)"/>
<line x1="478" y1="318" x2="304" y2="318" class="d-line-fast" marker-end="url(#dg-a3f)"/>
<text x="492" y="322" class="d-small d-tfast">SNI shop.test ok → mark 1</text>
<text x="190" y="340" text-anchor="middle" class="d-small d-tfast">ct mark set 1 (stored)</text>
<line x1="302" y1="366" x2="676" y2="366" class="d-line" marker-end="url(#dg-a3)"/>
<line x1="82" y1="406" x2="676" y2="406" class="d-line-fast" marker-end="url(#dg-a3f)"/>
<line x1="678" y1="430" x2="84" y2="430" class="d-line-fast" marker-end="url(#dg-a3f)"/>
<text x="90" y="400" class="d-bold d-tfast">5… every later packet, both directions</text>
<text x="190" y="452" text-anchor="middle" class="d-small d-tfast">ct mark 1: accepted by kernel</text>
</svg>
</div>
<figcaption>Three packets of this connection visit the engine; the server's replies never do. Once the ClientHello is read, everything else stays in the kernel.</figcaption>
</figure>

1. **SYN.** No ct mark, so it's queued. The engine checks the rate limit and the rules (`allow-web` matches), but the site name hasn't arrived yet, so it answers mark 3: let this packet through, keep watching.
2. **SYN-ACK.** A reply, accepted by the kernel.
3. **ACK.** Still no verdict and no data, so mark 3 again.
4. **ClientHello.** The first byte is `0x16`, a TLS handshake. The engine walks to the server name (SNI) extension, reads `shop.test`, and answers mark 1. The kernel stores ct mark 1.
5. **Everything else** matches `ct mark 1 accept` and never leaves the kernel.

Had the name been `evil.test`, step 4 would answer mark 4: the client gets a TCP reset, and any further packet on that connection is rejected by the kernel. Connections with nothing to inspect, like ping or iperf, get mark 1 on their first packet.

| Mark | Verdict | Stored on the connection |
|---|---|---|
| 1 | Allow connection | Yes: fast path from now on |
| 2 | Drop connection | Yes |
| 3 | Allow this packet, keep inspecting | No |
| 4 | Reject connection (TCP reset or ICMP) | Yes |
| 5 | Reject this packet (DNS) | No |
| none | Drop this packet (`NF_DROP`, rate limiting) | No: a retry is judged again |

## How the engine decides

**The first packet of a new connection:**

1. **Banned source?** Drop it. The kernel's ban rule normally catches these first; this covers packets already queued when the ban landed.
2. **Rate limit.** Take a token from the source's bucket (see [Rate limiting and bans](#rate-limiting-and-bans)). An empty bucket drops the packet with nothing stored.
3. **Rules,** top to bottom, first match wins; no match means the `drop` default. Drop and reject are decided here and stored.
4. **Allowed:**
   - DNS (UDP 53): each query name is checked against the blocklist, and the flow is never offloaded, because one UDP 5-tuple can carry many queries.
   - TCP when there are domains to block: wait for the first data packet.
   - Anything else: mark 1 straight away.

**A later packet of a connection still under inspection:** if it carries data, read the TLS server name or the HTTP Host header and answer mark 4 (blocked) or mark 1 (allowed). A connection that sends no data within 8 packets is released; one that closes before sending data is forgotten.

**Limits:** decided connections live only in the kernel, so the engine's memory holds just the ones under inspection, at most 65,536. When that table is full, new connections that need inspection are dropped rather than let through unchecked.

## Who it protects

A firewall guards traffic in both directions, and Gatekeep does both:

- **Inbound, protecting servers:** port rules (reject telnet, drop SSH), blocking specific sources (the quarantined host) and rate limiting connection floods. These stop unwanted traffic reaching the machines behind the firewall.
- **Outbound, protecting clients:** the domain blocklist stops machines behind the firewall from reaching phishing sites, malware control servers or trackers. Picture the client as an office laptop and the server as the internet.

Blocking by name instead of by IP matters because one IP address can host thousands of websites (CDNs and cloud providers), and a bad site can move to a new address tomorrow. So the client has to tell the server which site it wants: in the TLS ClientHello's server name (SNI), sent before encryption starts, or in the HTTP `Host` header. Gatekeep reads that same field.

In the lab every `*.test` name points at the same server: the scenarios pass curl `--resolve evil.test:443:10.10.2.10`, and the lab's DNS answers any `*.test` with 10.10.2.10. The server answers whatever name it's asked for, so the name in the connection is all that tells `shop.test` and `evil.test` apart.

## Rate limiting and bans

**What's counted:** new connections, per **source IP address**. Not packets, bytes or ports. Packets of an already-allowed connection never reach the engine, so they aren't counted.

**How one machine makes many connections:** each connection gets a different source port, so one client can open thousands, all from one IP. The SYN flood scenario sends 3,000 connection attempts at 2,000 per second from 10.10.1.10, and all of them count against that one IP.

**The token bucket:** each source IP has a bucket of up to **100** tokens, refilled at **50 per second**, and each new connection takes one. A browser opening 20 connections at once fits easily. When the bucket is empty, the attempt is dropped and the source gets a **strike**. At **200 strikes**, the source is banned:

- its IP goes into the kernel's `@banned` set for 30 seconds, so everything from it is dropped before the engine sees it;
- its existing connections are deleted from conntrack, so its fast-path traffic stops too;
- after 30 seconds the kernel removes the entry by itself. `DELETE /bans/{ip}` lifts it early.

In the recorded flood, about 100 attempts get through on the burst, the source is banned a fraction of a second later, and about 2,700 more are dropped by the kernel.

| | Reject (mark 4) | Ban |
|---|---|---|
| Applies to | One connection | A whole source IP |
| Stored in | That connection's ct mark | The `@banned` nftables set |
| Set when | A rule says reject, or the domain is blocked | The source floods new connections |
| Lasts | As long as the connection | 30 seconds |

**What it doesn't cover:** a flood *inside* an already-allowed connection. Its packets carry ct mark 1, so the kernel forwards them without the engine; that's the fast path's trade-off. A per-source packet-rate `meter` in nftables above the fast-path rule, or `ct count` to cap concurrent connections, would close it. Floods from spoofed random addresses spread across many buckets and need SYN cookies and a global limit.

## How the website talks to the lab

**Demo** replays a recorded session (`web/public/replay.json`) and needs no backend. **Live** drives a running lab through two small APIs:

<figure class="diagram">
<div class="diagram-scroll">
<svg viewBox="0 0 760 300" role="img" aria-label="The Live page sends scenario runs to the runner in the client container on port 8081, which runs curl through the firewall to the server; it polls and controls the engine's API in the firewall container on port 8080.">
<defs>
<marker id="dg-a4" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah"/></marker>
<marker id="dg-a4s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="d-ah-slow"/></marker>
</defs>
<rect x="10" y="110" width="150" height="80" rx="8" class="d-box"/>
<text x="85" y="140" text-anchor="middle" class="d-bold">browser</text>
<text x="85" y="160" text-anchor="middle" class="d-small">Live page</text>
<rect x="250" y="20" width="200" height="80" rx="8" class="d-box"/>
<text x="350" y="48" text-anchor="middle" class="d-bold">client container</text>
<text x="350" y="68" text-anchor="middle" class="d-small">scenario runner :8081</text>
<text x="350" y="86" text-anchor="middle" class="d-small">runs curl, dig, hping3…</text>
<rect x="250" y="200" width="200" height="80" rx="8" class="d-fast-box"/>
<text x="350" y="228" text-anchor="middle" class="d-bold d-tfast">firewall container</text>
<text x="350" y="248" text-anchor="middle" class="d-small">engine (C++)</text>
<text x="350" y="266" text-anchor="middle" class="d-small">control API :8080</text>
<rect x="560" y="110" width="180" height="80" rx="8" class="d-box"/>
<text x="650" y="140" text-anchor="middle" class="d-bold">server container</text>
<text x="650" y="160" text-anchor="middle" class="d-small">answers allowed traffic</text>
<line x1="140" y1="108" x2="246" y2="62" class="d-line" marker-end="url(#dg-a4)"/>
<text x="150" y="70" class="d-small">POST /run/&lt;id&gt;</text>
<line x1="140" y1="192" x2="246" y2="238" class="d-line" marker-end="url(#dg-a4)"/>
<text x="128" y="244" text-anchor="end" class="d-small">every 0.7 s +</text>
<text x="128" y="260" text-anchor="end" class="d-small">controls</text>
<path d="M350,102 L350,196" class="d-line-slow" marker-end="url(#dg-a4s)"/>
<text x="358" y="150" class="d-small d-tslow">real traffic from 10.10.1.10</text>
<path d="M452,232 C520,232 520,170 556,160" class="d-line-slow" marker-end="url(#dg-a4s)"/>
<text x="500" y="210" class="d-small d-tslow">if allowed</text>
</svg>
</div>
<figcaption>Scenario buttons go to the client's runner, which sends real traffic through the firewall. Counters, decisions, policy and controls go to the firewall's own API. The website never talks to the server.</figcaption>
</figure>

When you press **Visit evil.test over HTTPS** on the Live page:

1. The browser sends `POST http://127.0.0.1:8081/run/tls-blocked` to the **runner** in the client container.
2. The runner runs `curl … https://evil.test/` there, so the packets leave from 10.10.1.10 and cross the firewall.
3. The firewall reads `evil.test` from the ClientHello and resets the connection.
4. curl fails; the runner streams the step back as `blocked`.
5. Meanwhile the page polls the engine's API and shows the new decision and the kernel's packet counters.

The runner has to live in the client container because the firewall only sees traffic that crosses it: the traffic must start inside the client's network, and a browser can't send packets from another machine. It can only run the fixed scenarios in `docker/lab/scenarios.py`, one at a time.
