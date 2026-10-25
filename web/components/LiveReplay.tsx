"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { CheckIcon, CrossIcon, OutcomeTag } from "./Icons";
import { at, fmt, outcomeOf, reasonText, verdictText, type Decision, type Replay, type Scenario, type Step } from "@/lib/replay";

const SPEEDS = [1, 2, 4];

export function LiveReplay() {
  const [replay, setReplay] = useState<Replay | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/replay.json")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setReplay)
      .catch((e) => setError(String(e)));
  }, []);

  if (error) return <p className="replay-empty">The recorded session couldn&apos;t be loaded ({error}). Reload the page to try again.</p>;
  if (!replay) return <p className="replay-empty">Loading the recorded session…</p>;
  return <Player replay={replay} />;
}

function Player({ replay }: { replay: Replay }) {
  const [t, setT] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [only, setOnly] = useState<Scenario | null>(null); // playing a single scenario
  const tRef = useRef(0);
  tRef.current = t;

  useEffect(() => {
    if (!playing) return;
    let raf = 0;
    let last = performance.now();
    const end = only ? only.t1 : replay.duration;
    const tick = (now: number) => {
      const next = Math.min(end, tRef.current + ((now - last) / 1000) * speed);
      last = now;
      setT(next);
      if (next >= end) {
        setPlaying(false);
        return;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing, speed, only, replay.duration]);

  const stageRef = useRef<HTMLDivElement>(null);
  const playScenario = useCallback((s: Scenario, scroll = false) => {
    setOnly(s);
    setT(s.t0);
    setPlaying(true);
    // On narrow screens the list sits above the player: bring the player into view.
    if (scroll && window.matchMedia("(max-width: 960px)").matches) {
      stageRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, []);

  // /demo?scenario=<id> plays that scenario; /demo?t=<seconds> opens paused at that moment.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const s = replay.scenarios.find((sc) => sc.id === params.get("scenario"));
    const seek = Number(params.get("t"));
    if (params.has("t") && seek >= 0 && seek <= replay.duration) setT(seek);
    else if (s) playScenario(s);
  }, [replay, playScenario]);

  const playAll = () => {
    setOnly(null);
    if (t >= replay.duration - 0.05) setT(0);
    setPlaying(true);
  };

  const first = replay.frames[0];
  const frame = at(replay.frames, t);
  const policy = at(replay.policies, t).policy;
  const initialRules = useMemo(() => new Set(replay.policies[0].policy.rules.map((r) => r.id)), [replay]);
  const decisions = useMemo(() => replay.events.filter((e) => e.t <= t), [replay, t]);
  const current = [...replay.scenarios].reverse().find((s) => s.t0 <= t) ?? null;
  const started = t > 0;

  return (
    <div className="player">
      <div className="player-bar">
        <div className="transport">
          {playing ? (
            <button className="button button-dark" onClick={() => setPlaying(false)}>
              Pause
            </button>
          ) : (
            <button className="button button-dark" onClick={playAll}>
              {started && !only && t < replay.duration - 0.05 ? "Resume" : "Play the whole session"}
            </button>
          )}
          <div className="speed" role="group" aria-label="Playback speed">
            {SPEEDS.map((s) => (
              <button key={s} aria-pressed={speed === s} onClick={() => setSpeed(s)}>
                {s}×
              </button>
            ))}
          </div>
        </div>
        <Timeline replay={replay} t={t} onSeek={(v) => { setOnly(null); setT(v); }} />
      </div>

      <div className="player-grid">
        <nav className="scenarios" aria-label="Scenarios">
          <h2>Scenarios</h2>
          <ol>
            {replay.scenarios.map((s) => {
              const done = t >= s.t1;
              const active = current?.id === s.id && t < s.t1;
              return (
                <li key={s.id}>
                  <button className={active ? "scenario is-active" : "scenario"} onClick={() => playScenario(s, true)} aria-current={active ? "step" : undefined}>
                    <span className="scenario-title">{s.title}</span>
                    <span className="scenario-results" aria-label={done ? "Outcomes" : undefined}>
                      {done &&
                        s.steps
                          .filter((st): st is Extract<Step, { kind: "traffic" }> => st.kind === "traffic" && st.outcome !== "sent")
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
        </nav>

        <div className="stage" ref={stageRef}>
          {current ? (
            <ScenarioPanel scenario={current} t={t} />
          ) : (
            <div className="stage-empty">
              <h2>Pick a scenario to watch</h2>
              <p>
                Each one replays commands sent from the client container through the firewall, and what the engine
                decided. Or play the whole {Math.round(replay.duration)}-second session from the start.
              </p>
            </div>
          )}

          <section className="counters" aria-label="Counters since the session started">
            <Counter label="Packets in the kernel lane" value={(frame.kernel.fast ?? 0) - (first.kernel.fast ?? 0)} tone="fast" />
            <Counter label="Packets seen by the engine" value={frame.packets_inspected - first.packets_inspected} tone="engine" />
            <Counter label="Packets dropped from banned sources" value={(frame.kernel.banned_drops ?? 0) - (first.kernel.banned_drops ?? 0)} tone="stop" />
            <Counter label="Sources banned now" value={frame.active_bans} tone="plain" />
          </section>

          <div className="stage-split">
            <DecisionLog decisions={decisions} />
            <RulesPanel rules={policy.rules} domains={policy.blocked_domains} isNew={(id) => !initialRules.has(id)} defaultAction={policy.default_action} />
          </div>
        </div>
      </div>
    </div>
  );
}

function Timeline({ replay, t, onSeek }: { replay: Replay; t: number; onSeek: (t: number) => void }) {
  const pct = (v: number) => `${(v / replay.duration) * 100}%`;
  return (
    <div className="timeline">
      <div className="timeline-track" aria-hidden="true">
        {replay.scenarios.map((s, i) => (
          <span key={s.id} className={i % 2 ? "segment segment-b" : "segment"} style={{ left: pct(s.t0), width: pct(s.t1 - s.t0) }} title={s.title} />
        ))}
        {replay.events.map((e, i) => (
          <span key={i} className={`tick tick-${outcomeOf(e.verdict)}`} style={{ left: pct(e.t) }} />
        ))}
        <span className="playhead" style={{ left: pct(t) }} />
      </div>
      <input
        type="range"
        min={0}
        max={replay.duration}
        step={0.1}
        value={t}
        onChange={(e) => onSeek(Number(e.target.value))}
        aria-label="Session time"
        aria-valuetext={`${t.toFixed(1)} of ${replay.duration.toFixed(0)} seconds`}
      />
      <span className="timeline-time">
        {t.toFixed(1)}s / {replay.duration.toFixed(0)}s
      </span>
    </div>
  );
}

function ScenarioPanel({ scenario, t }: { scenario: Scenario; t: number }) {
  return (
    <section className="scenario-panel" aria-live="polite">
      <h2>{scenario.title}</h2>
      <p className="scenario-summary">{scenario.summary}</p>
      <ol className="steps">
        {scenario.steps.map((st, i) => {
          const state = t < st.t0 ? "upcoming" : t < st.t1 ? "running" : "done";
          return (
            <li key={i} className={`step step-${state}`}>
              <div className="step-head">
                <span className="step-label">{st.label}</span>
                {state === "running" && <OutcomeTag outcome="running" />}
                {state === "done" && st.kind === "traffic" && <OutcomeTag outcome={st.outcome} />}
                {state === "done" && st.kind === "api" && (
                  <span className="tag tag-allowed">
                    <CheckIcon />
                    Applied
                  </span>
                )}
              </div>
              <code className="step-command">
                {st.kind === "api" ? "api " : "client $ "}
                {st.command}
              </code>
              {state === "done" && st.kind === "traffic" && st.output && <pre className="step-output">{st.output.trim().split("\n").slice(-2).join("\n")}</pre>}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function Counter({ label, value, tone }: { label: string; value: number; tone: "fast" | "engine" | "stop" | "plain" }) {
  return (
    <div className={`counter counter-${tone}`}>
      <span className="counter-value">{fmt(Math.max(0, value))}</span>
      <span className="counter-label">{label}</span>
    </div>
  );
}

function DecisionLog({ decisions }: { decisions: Decision[] }) {
  const rows = [...decisions].reverse().slice(0, 40);
  return (
    <section className="decisions" aria-label="Engine decisions, newest first">
      <h2>Engine decisions</h2>
      {rows.length === 0 ? (
        <p className="muted">No decisions yet. They appear here as the engine makes them.</p>
      ) : (
        <ol className="decision-list">
          {rows.map((d, i) => {
            const outcome = outcomeOf(d.verdict);
            const target = d.host ?? `${d.dst}${d.dst_port ? `:${d.dst_port}` : ""}`;
            const why = explain(d);
            return (
              <li key={`${d.t}-${i}`} className="decision">
                <span className="decision-time">{d.t.toFixed(1)}s</span>
                <div>
                  <div className="decision-head">
                    <span className={`tag tag-${outcome}`}>
                      {outcome === "allowed" ? <CheckIcon /> : <CrossIcon />}
                      {verdictText[d.verdict]}
                    </span>
                    <strong className="decision-target">{target}</strong>
                  </div>
                  <p className="decision-detail">
                    {d.proto} from {d.src}
                    {d.src_port ? `:${d.src_port}` : ""} to {d.dst}
                    {d.dst_port ? `:${d.dst_port}` : ""}. {why}
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

function explain(d: Decision): string {
  if (d.rule === "default") return "No rule matched, so the default policy dropped it.";
  switch (d.reason) {
    case "policy":
      return `Matched rule ${d.rule}.`;
    case "inspected":
      return `Rule ${d.rule} allowed it, and the first payload was clean.`;
    case "domain_blocked":
      return "The name is on the blocklist.";
    case "rate_limit_ban":
      return `Over the new-connection limit 200 times: source banned for ${d.ban_seconds ?? 30} seconds.`;
    default:
      return `${reasonText[d.reason] ?? d.reason}.`;
  }
}

function RulesPanel({
  rules,
  domains,
  isNew,
  defaultAction,
}: {
  rules: Replay["policies"][number]["policy"]["rules"];
  domains: string[];
  isNew: (id: string) => boolean;
  defaultAction: string;
}) {
  return (
    <section className="rules" aria-label="Current policy">
      <h2>Policy</h2>
      <ol className="rule-list">
        {rules.map((r) => (
          <li key={r.id} className={isNew(r.id) ? "rule is-new" : "rule"}>
            <span className={`rule-action rule-${r.action}`}>{r.action}</span>
            <span className="rule-match">
              {[r.proto, r.src && `from ${r.src}`, r.dst && `to ${r.dst}`, r.dst_ports && `port ${r.dst_ports}`].filter(Boolean).join(" ") || "anything"}
            </span>
            <span className="rule-id">{isNew(r.id) ? `${r.id}, just added` : r.id}</span>
          </li>
        ))}
        <li className="rule rule-default">
          <span className={`rule-action rule-${defaultAction}`}>{defaultAction}</span>
          <span className="rule-match">anything else</span>
          <span className="rule-id">default</span>
        </li>
      </ol>
      <h3>Blocked domains</h3>
      <p className="domains">{domains.map((d) => <code key={d}>{d}</code>)}</p>
    </section>
  );
}
