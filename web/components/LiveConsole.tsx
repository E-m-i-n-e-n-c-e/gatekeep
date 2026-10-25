"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { CheckIcon, CrossIcon, OutcomeTag } from "./Icons";
import { API_URL, ApiError, RUNNER_URL, call, canConnect } from "@/lib/endpoints";
import { clock, explain } from "@/lib/explain";
import {
  initBaseline,
  requestStop,
  runAll,
  runScenario,
  setBaseline,
  useSession,
  type ScenarioInfo,
} from "@/lib/liveSession";
import { fmt, outcomeOf, verdictText, type Decision, type Policy, type Rule } from "@/lib/replay";
import { GITHUB } from "@/lib/site";

// Live mode: talks to a running firewall (control API) and the lab's scenario
// runner. Separate from the recorded demo on purpose; they share only icons.

const POLL_MS = 700;

type Status = "checking" | "connected" | "offline" | "unavailable";

interface Kernel {
  fast: number;
  slow: number;
  banned_drops: number;
}

interface Stats {
  packets_inspected: number;
  active_bans: number;
}

interface Snapshot {
  stats: Stats;
  kernel: Kernel;
  events: Decision[];
  policy: Policy;
  bans: { ip: string; expires_in_s: number }[];
}

async function snapshot(): Promise<Snapshot> {
  const [stats, kernel, events, policy, bans] = await Promise.all([
    call<Stats>(API_URL, "GET", "/stats"),
    call<Kernel>(API_URL, "GET", "/kernel"),
    call<Decision[]>(API_URL, "GET", "/events?limit=60"),
    call<Policy>(API_URL, "GET", "/policy"),
    call<Snapshot["bans"]>(API_URL, "GET", "/bans"),
  ]);
  return { stats, kernel, events, policy, bans };
}

export function LiveConsole() {
  const session = useSession();
  const { run, results, playingAll, stopRequested, baseline, stepsDone } = session;
  const [status, setStatus] = useState<Status>("checking");
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [fastPath, setFastPath] = useState(true);
  const [scenarios, setScenarios] = useState<ScenarioInfo[] | null>(null);
  const [runnerBusy, setRunnerBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>();

  const refresh = useCallback(async () => {
    try {
      const s = await snapshot();
      setSnap(s);
      initBaseline({ fast: s.kernel.fast, banned_drops: s.kernel.banned_drops, inspected: s.stats.packets_inspected });
      setStatus("connected");
      call<{ busy: boolean }>(RUNNER_URL, "GET", "/health").then((h) => setRunnerBusy(h.busy), () => setRunnerBusy(false));
      return true;
    } catch {
      setStatus((prev) => (prev === "unavailable" ? prev : "offline"));
      return false;
    }
  }, []);

  // Poll while connected; retry every few seconds while offline.
  useEffect(() => {
    if (!canConnect()) {
      setStatus("unavailable");
      return;
    }
    let alive = true;
    const loop = async () => {
      const ok = await refresh();
      if (alive) timer.current = setTimeout(loop, ok ? POLL_MS : 3000);
    };
    loop();
    return () => {
      alive = false;
      clearTimeout(timer.current);
    };
  }, [refresh]);

  // A step just finished: refresh now instead of waiting for the next poll.
  useEffect(() => {
    if (stepsDone > 0) refresh();
  }, [stepsDone, refresh]);

  // Once connected: the fast-path setting and the runner's scenarios.
  useEffect(() => {
    if (status !== "connected") return;
    call<{ fast_path: boolean }>(API_URL, "GET", "/config").then((c) => setFastPath(c.fast_path), () => {});
    if (!scenarios) {
      call<ScenarioInfo[]>(RUNNER_URL, "GET", "/scenarios").then(setScenarios, () => setScenarios([]));
    }
  }, [status, scenarios]);

  // Runs a control-API change, shows any error, then refreshes right away.
  const act = async (fn: () => Promise<unknown>, done?: string) => {
    try {
      await fn();
      setNotice(done ?? null);
    } catch (e) {
      setNotice(e instanceof ApiError ? `The firewall refused that: ${e.message}` : "The firewall didn't answer. Is the lab still running?");
    }
    refresh();
  };

  if (status === "unavailable") return <Unavailable />;
  if (status === "checking" && !snap) return <p className="replay-empty">Looking for a firewall at {API_URL}…</p>;
  if (!snap || !baseline) return <Offline />;

  const running = run !== null && !run.finished;
  // The lab is busy with a run this page didn't start (e.g. before a reload).
  const busyElsewhere = runnerBusy && !running;
  const counters = {
    fast: snap.kernel.fast - baseline.fast,
    engine: snap.stats.packets_inspected - baseline.inspected,
    banned: snap.kernel.banned_drops - baseline.banned_drops,
  };

  return (
    <div className="player">
      <div className="live-bar" role="region" aria-label="Connection and controls">
        <span className={status === "connected" ? "conn-state is-up" : "conn-state is-down"}>
          {status === "connected" ? <CheckIcon /> : <CrossIcon />}
          {status === "connected" ? `Connected to ${API_URL}` : `Lost ${API_URL}, retrying`}
        </span>
        <div className="live-actions">
          <label className="switch">
            <input
              type="checkbox"
              checked={fastPath}
              onChange={(e) => {
                const on = e.target.checked;
                setFastPath(on);
                act(() => call(API_URL, "PUT", "/config", { fast_path: on }), on ? "Fast path on: allowed connections go back to the kernel." : "Fast path off: every packet now goes through the engine.");
              }}
            />
            <span>Fast path</span>
          </label>
          <button className="button button-quiet" onClick={() => act(() => call(API_URL, "POST", "/policy/reload"), "Policy reset to the file.")}>
            Reset policy
          </button>
          <button className="button button-quiet" onClick={() => setBaseline({ fast: snap.kernel.fast, banned_drops: snap.kernel.banned_drops, inspected: snap.stats.packets_inspected })}>
            Zero counters
          </button>
        </div>
      </div>
      {notice && (
        <p className="live-notice" role="status">
          {notice}
          <button onClick={() => setNotice(null)} aria-label="Dismiss">
            <CrossIcon />
          </button>
        </p>
      )}

      <div className="player-grid">
        <nav className="scenarios" aria-label="Scenarios">
          <h2>Run a scenario</h2>
          {scenarios && scenarios.length > 0 &&
            (playingAll ? (
              <button className="button button-quiet run-all" onClick={requestStop} disabled={stopRequested}>
                {stopRequested ? "Stopping after this scenario…" : "Stop after this scenario"}
              </button>
            ) : (
              <button className="button button-dark run-all" onClick={() => runAll(scenarios)} disabled={running || busyElsewhere}>
                Run all {scenarios.length} in order
              </button>
            ))}
          {busyElsewhere && <p className="muted">The lab is finishing a scenario started earlier. The buttons unlock when it&apos;s done.</p>}
          {scenarios === null ? (
            <p className="muted">Loading scenarios…</p>
          ) : scenarios.length === 0 ? (
            <p className="muted">The scenario runner isn&apos;t answering at {RUNNER_URL}. The controls still work.</p>
          ) : (
            <ol>
              {scenarios.map((s) => {
                const active = run?.scenario.id === s.id && running;
                const last = results[s.id];
                return (
                  <li key={s.id}>
                    <button className={active ? "scenario is-active" : "scenario"} onClick={() => runScenario(s)} disabled={running || playingAll || busyElsewhere} aria-current={active ? "step" : undefined}>
                      <span className="scenario-title">{s.title}</span>
                      <span className="scenario-results">
                        {last
                          ?.filter((st) => st.kind === "traffic" && st.outcome !== "sent")
                          .map((st, i) =>
                            st.outcome === "allowed" ? (
                              <span key={i} className="tag tag-allowed" title={`${st.label}: allowed`}>
                                <CheckIcon />
                              </span>
                            ) : (
                              <span key={i} className="tag tag-blocked" title={`${st.label}: blocked`}>
                                <CrossIcon />
                              </span>
                            ),
                          )}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ol>
          )}
        </nav>

        <div className="stage">
          {run ? (
            <section className="scenario-panel" aria-live="polite">
              <h2>{run.scenario.title}</h2>
              <p className="scenario-summary">{run.scenario.summary}</p>
              {run.error && <p className="live-error">{run.error}</p>}
              <ol className="steps">
                {run.steps.map((st, i) => (
                  <li key={i} className={`step step-${st.state}`}>
                    <div className="step-head">
                      <span className="step-label">{st.label}</span>
                      {st.state === "running" && <OutcomeTag outcome="running" />}
                      {st.state === "done" && st.kind === "traffic" && st.outcome && <OutcomeTag outcome={st.outcome} />}
                      {st.state === "done" && st.kind === "api" && (
                        <span className={st.status && st.status < 300 ? "tag tag-allowed" : "tag tag-blocked"}>
                          {st.status && st.status < 300 ? <CheckIcon /> : <CrossIcon />}
                          {st.status && st.status < 300 ? "Applied" : `Refused (${st.status})`}
                        </span>
                      )}
                    </div>
                    <code className="step-command">
                      {st.kind === "api" ? "api " : "client $ "}
                      {st.command}
                    </code>
                    {st.state === "done" && st.output && <pre className="step-output">{st.output.trim().split("\n").slice(-2).join("\n")}</pre>}
                  </li>
                ))}
              </ol>
            </section>
          ) : (
            <div className="stage-empty">
              <h2>Pick a scenario to run</h2>
              <p>
                It sends real traffic from the client container through the firewall. The counters, decisions and policy
                below are read from the firewall as it works.
              </p>
            </div>
          )}

          <section className="counters" aria-label="Counters since this page opened">
            <LiveCounter label="Packets in the kernel lane" value={counters.fast} tone="fast" />
            <LiveCounter label="Packets seen by the engine" value={counters.engine} tone="engine" />
            <LiveCounter label="Packets dropped from banned sources" value={counters.banned} tone="stop" />
            <LiveCounter label="Sources banned now" value={snap.stats.active_bans} tone="plain" />
          </section>

          <div className="stage-split">
            <LiveDecisions events={snap.events} />
            <LivePolicy policy={snap.policy} bans={snap.bans} act={act} />
          </div>
        </div>
      </div>
    </div>
  );
}

function LiveCounter({ label, value, tone }: { label: string; value: number; tone: "fast" | "engine" | "stop" | "plain" }) {
  return (
    <div className={`counter counter-${tone}`}>
      <span className="counter-value">{fmt(Math.max(0, value))}</span>
      <span className="counter-label">{label}</span>
    </div>
  );
}

function LiveDecisions({ events }: { events: Decision[] }) {
  const rows = [...events].reverse();
  return (
    <section className="decisions" aria-label="Engine decisions, newest first">
      <h2>Engine decisions</h2>
      {rows.length === 0 ? (
        <p className="muted">No decisions yet. Run a scenario and they appear here as the engine makes them.</p>
      ) : (
        <ol className="decision-list">
          {rows.map((d, i) => {
            const outcome = outcomeOf(d.verdict);
            return (
              <li key={`${d.ts}-${d.src_port}-${i}`} className="decision decision-live">
                <span className="decision-time">{clock(d.ts)}</span>
                <div>
                  <div className="decision-head">
                    <span className={`tag tag-${outcome}`}>
                      {outcome === "allowed" ? <CheckIcon /> : <CrossIcon />}
                      {verdictText[d.verdict]}
                    </span>
                    <strong className="decision-target">{d.host ?? `${d.dst}${d.dst_port ? `:${d.dst_port}` : ""}`}</strong>
                  </div>
                  <p className="decision-detail">
                    {d.proto} from {d.src}
                    {d.src_port ? `:${d.src_port}` : ""} to {d.dst}
                    {d.dst_port ? `:${d.dst_port}` : ""}. {explain(d)}
                  </p>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

function describe(r: Rule) {
  return [r.proto, r.src && `from ${r.src}`, r.dst && `to ${r.dst}`, r.dst_ports && `port ${r.dst_ports}`].filter(Boolean).join(" ") || "anything";
}

function LivePolicy({
  policy,
  bans,
  act,
}: {
  policy: Policy;
  bans: Snapshot["bans"];
  act: (fn: () => Promise<unknown>, done?: string) => void;
}) {
  const [domain, setDomain] = useState("");
  const [rule, setRule] = useState({ id: "", action: "reject", proto: "tcp", dst_ports: "" });

  const addRule = (e: React.FormEvent) => {
    e.preventDefault();
    const body: Record<string, string> = { id: rule.id.trim(), action: rule.action, proto: rule.proto };
    if (rule.dst_ports.trim()) body.dst_ports = rule.dst_ports.trim();
    act(() => call(API_URL, "POST", "/rules?position=0", body), `Rule ${body.id} added at the top.`);
    setRule((r) => ({ ...r, id: "", dst_ports: "" }));
  };

  return (
    <section className="rules" aria-label="Current policy">
      <h2>Policy</h2>
      <ol className="rule-list">
        {policy.rules.map((r) => (
          <li key={r.id} className="rule rule-live">
            <span className={`rule-action rule-${r.action}`}>{r.action}</span>
            <span className="rule-match">{describe(r)}</span>
            <span className="rule-id">{r.id}</span>
            <button
              className="icon-button"
              onClick={() => act(() => call(API_URL, "DELETE", `/rules/${encodeURIComponent(r.id)}`), `Rule ${r.id} removed.`)}
              aria-label={`Delete rule ${r.id}`}
              title="Delete rule"
            >
              <CrossIcon />
            </button>
          </li>
        ))}
        <li className="rule rule-default">
          <span className={`rule-action rule-${policy.default_action}`}>{policy.default_action}</span>
          <span className="rule-match">anything else</span>
          <span className="rule-id">default</span>
        </li>
      </ol>

      <form className="live-form" onSubmit={addRule} aria-label="Add a rule at the top">
        <h3>Add a rule at the top</h3>
        <div className="form-row">
          <label>
            <span>Name</span>
            <input required value={rule.id} onChange={(e) => setRule({ ...rule, id: e.target.value })} placeholder="block-web" pattern="[A-Za-z0-9._\-]{1,64}" />
          </label>
          <label>
            <span>Action</span>
            <select value={rule.action} onChange={(e) => setRule({ ...rule, action: e.target.value })}>
              <option value="allow">allow</option>
              <option value="drop">drop</option>
              <option value="reject">reject</option>
            </select>
          </label>
          <label>
            <span>Protocol</span>
            <select value={rule.proto} onChange={(e) => setRule({ ...rule, proto: e.target.value })}>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
              <option value="any">any</option>
            </select>
          </label>
          <label>
            <span>Ports</span>
            <input value={rule.dst_ports} onChange={(e) => setRule({ ...rule, dst_ports: e.target.value })} placeholder="80,443" disabled={rule.proto !== "tcp" && rule.proto !== "udp"} />
          </label>
        </div>
        <button className="button button-dark" type="submit">
          Add rule
        </button>
      </form>

      <h3>Blocked domains</h3>
      <ul className="domains domains-live">
        {policy.blocked_domains.map((d) => (
          <li key={d}>
            <code>{d}</code>
            <button
              className="icon-button"
              onClick={() => act(() => call(API_URL, "DELETE", `/domains/${encodeURIComponent(d)}`), `${d} unblocked.`)}
              aria-label={`Unblock ${d}`}
              title="Unblock"
            >
              <CrossIcon />
            </button>
          </li>
        ))}
      </ul>
      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          const d = domain.trim();
          if (!d) return;
          act(() => call(API_URL, "POST", "/domains", { domain: d }), `${d} blocked.`);
          setDomain("");
        }}
      >
        <label className="visually-hidden" htmlFor="new-domain">
          Domain to block
        </label>
        <input id="new-domain" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="shop.test" />
        <button className="button button-dark" type="submit">
          Block domain
        </button>
      </form>

      <h3>Banned sources</h3>
      {bans.length === 0 ? (
        <p className="muted">None. Run the SYN flood scenario to get one banned.</p>
      ) : (
        <ul className="ban-list">
          {bans.map((b) => (
            <li key={b.ip}>
              <span>
                <strong>{b.ip}</strong> <span className="muted">for {b.expires_in_s}s more</span>
              </span>
              <button className="button button-quiet" onClick={() => act(() => call(API_URL, "DELETE", `/bans/${b.ip}`), `${b.ip} unbanned.`)}>
                Lift ban
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Unavailable() {
  return (
    <div className="stage-empty live-setup">
      <h2>Live mode runs against your own lab</h2>
      <p>
        This copy of the site is on the internet, so it can&apos;t reach a firewall on your computer. Watch the{" "}
        <Link href="/demo">recorded demo</Link>, or run everything locally:
      </p>
      <Setup />
    </div>
  );
}

function Offline() {
  return (
    <div className="stage-empty live-setup">
      <h2>No firewall found yet</h2>
      <p>
        Looking for the control API at <code>{API_URL}</code> and retrying every few seconds. Start the lab and this page
        connects by itself. Meanwhile, the <Link href="/demo">recorded demo</Link> shows a real session.
      </p>
      <Setup />
    </div>
  );
}

function Setup() {
  return (
    <ol className="setup-steps">
      <li>
        <code>git clone {GITHUB}.git &amp;&amp; cd gatekeep</code>
      </li>
      <li>
        <code>docker compose up -d --build</code> starts the client, the firewall and the server.
      </li>
      <li>
        <code>cd web &amp;&amp; npm install &amp;&amp; npm run dev</code>, then open <code>http://localhost:3000/live</code>.
      </li>
    </ol>
  );
}
