import Link from "next/link";

import { BenchChart } from "@/components/BenchChart";
import { LaneHero } from "@/components/LaneHero";
import { bulkSplit, loadReplay } from "@/lib/load";
import { fmt } from "@/lib/replay";
import { GITHUB } from "@/lib/site";

const JOURNEY = [
  {
    where: "engine",
    title: "SYN arrives",
    text: "The connection has no verdict yet, so the kernel queues the packet to the engine. The engine checks the rate limit and the rules: allow-web matches. It lets the packet through but keeps watching.",
  },
  {
    where: "kernel",
    title: "Handshake completes",
    text: "The server's reply belongs to a tracked connection, so the kernel accepts it on its own. The client's ACK goes back to the engine, which is still waiting for data.",
  },
  {
    where: "engine",
    title: "First data packet",
    text: "The TLS ClientHello names the site in plain text: shop.test. Not on the blocklist. Had it been evil.test, the connection would be reset here.",
  },
  {
    where: "kernel",
    title: "Verdict cached",
    text: "The engine marks the connection as allowed in the kernel's connection table. Every remaining packet, in both directions, is forwarded without leaving the kernel.",
  },
] as const;

export default function Home() {
  const replay = loadReplay();
  const split = bulkSplit(replay);
  const sample = (pred: (e: (typeof replay.events)[number]) => boolean) => replay.events.find(pred);
  const logs = {
    rule: sample((e) => e.rule === "reject-telnet"),
    domain: sample((e) => e.host === "cdn.evil.test"),
    flood: sample((e) => e.reason === "rate_limit_ban"),
  };
  // The engine's own log line, minus timing fields, spaced so it can wrap.
  const logLine = (e?: object) =>
    e
      ? JSON.stringify(e, (k, v) => (["t", "ts", "src_port"].includes(k) ? undefined : v))
          .replace(/","/g, '", "')
          .replace(/,"/g, ', "')
          .replace(/":/g, '": ')
      : "";

  return (
    <>
      <section className="hero">
        <div className="wrap">
          <div className="hero-copy">
            <h1>
              Decide once per connection.
              <br />
              Let the kernel carry the rest.
            </h1>
            <p className="hero-lede">
              Gatekeep is a stateful firewall for Linux, written in C++. It reads the first packets of every new
              connection, checks them against its rules and blocklist, and stores the verdict in the kernel. Every
              packet after that is forwarded by the kernel alone.
            </p>
            <div className="hero-actions">
              <Link href="/live" className="button button-primary">
                Watch the recorded demo
              </Link>
              <Link href="/docs" className="button button-quiet">
                Read how it works
              </Link>
            </div>
          </div>
          <LaneHero />
          <div className="hero-split" aria-label="Measured during a 3-second transfer">
            <p>
              <span className="split-number split-fast">{fmt(split.kernel)}</span>
              packets forwarded by the kernel lane
            </p>
            <p>
              <span className="split-number split-engine">{fmt(split.engine)}</span>
              packets that needed the engine
            </p>
            <p className="split-note">
              Measured during a 3-second, {split.gbps} Gbit/s transfer through the firewall, recorded in the demo.
            </p>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="wrap">
          <h2>What happens to a new connection</h2>
          <p className="section-lede">
            A client opens https://shop.test. Four moments decide where its packets go.
          </p>
          <ol className="journey">
            {JOURNEY.map((s) => (
              <li key={s.title} className={`journey-step journey-${s.where}`}>
                <span className="journey-where">{s.where === "engine" ? "In the engine" : "In the kernel"}</span>
                <h3>{s.title}</h3>
                <p>{s.text}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="section">
        <div className="wrap checks">
          <h2>What the engine checks</h2>
          <dl>
            <div>
              <dt>Addresses and ports</dt>
              <dd>
                <p>
                  Rules are read top to bottom and the first match wins: allow, drop, or reject with a TCP reset. Anything
                  no rule allows is dropped.
                </p>
                <pre className="log">{logLine(logs.rule)}</pre>
              </dd>
            </div>
            <div>
              <dt>The site a connection is for</dt>
              <dd>
                <p>
                  The name in a TLS ClientHello, an HTTP Host header or a DNS query is checked against a blocklist,
                  subdomains included. TLS is recognised by its bytes, so moving to another port doesn&apos;t hide it.
                </p>
                <pre className="log">{logLine(logs.domain)}</pre>
              </dd>
            </div>
            <div>
              <dt>Connection floods</dt>
              <dd>
                <p>
                  Each source gets a token bucket of new connections. A source that keeps exceeding it is banned in the
                  kernel for 30 seconds, and its open connections are cut.
                </p>
                <pre className="log">{logLine(logs.flood)}</pre>
              </dd>
            </div>
            <div>
              <dt>Its own failure</dt>
              <dd>
                <p>
                  If the engine stops, falls behind, or its table of connections under inspection fills up, packets are
                  dropped. Traffic is never let through unchecked.
                </p>
              </dd>
            </div>
          </dl>
        </div>
      </section>

      <section className="section">
        <div className="wrap bench-section">
          <div>
            <h2>Why the kernel lane matters</h2>
            <p className="section-lede">
              Small packets per second through the firewall, with the engine on the fast path and with every packet
              sent through it.
            </p>
            <p className="bench-cpu">
              On a 92 Gbit/s TCP stream the engine used <strong>about 0%</strong> of a CPU core with the fast path, and{" "}
              <strong>80%</strong> when it saw every packet.
            </p>
          </div>
          <BenchChart />
        </div>
      </section>

      <section className="section">
        <div className="wrap cta">
          <div>
            <h2>See it run</h2>
            <p>
              The demo page replays a real session: eleven scenarios, from an ordinary page load to a SYN flood, with
              every decision the engine made.
            </p>
            <Link href="/live" className="button button-dark">
              Open the demo
            </Link>
          </div>
          <div>
            <h2>Run it yourself</h2>
            <p>Three containers: a client, the firewall between two networks, and a server.</p>
            <pre className="code">
              <code>{`docker compose up -d --build\n./scripts/demo.sh`}</code>
            </pre>
            <a href={GITHUB}>Source and setup on GitHub</a>
          </div>
        </div>
      </section>
    </>
  );
}
