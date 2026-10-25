"use client";

import { useEffect, useRef, useState } from "react";

// The hero diagram: a road. Every new connection's first packet detours
// through the engine; once the engine rules, the rest of an allowed
// connection runs straight down the kernel lane. A blocked one ends there.

const KERNEL_PATH = "M0,84 L1000,84";
const DETOUR_PATH = "M0,84 L300,84 C365,84 360,226 432,226 L568,226 C640,226 635,84 700,84 L1000,84";

const CONNECTIONS = [
  { host: "shop.test", allowed: true },
  { host: "docs.test", allowed: true },
  { host: "evil.test", allowed: false },
  { host: "mail.test", allowed: true },
  { host: "tracker.test", allowed: false },
  { host: "news.test", allowed: true },
];

const SPAWN_EVERY = 1.7; // seconds between new connections
const DETOUR_SPEED = 300; // px/s for a first packet
const DWELL = 0.7; // seconds the engine holds it
const FAST_SPEED = 520; // px/s on the kernel lane
const FOLLOWERS = 9; // packets after the verdict
const FOLLOW_GAP = 0.16;

const COLORS = { inspect: "#f3c316", fast: "#4fd1a0", stop: "#ff6b7d" };

interface Dot {
  key: string;
  x: number;
  y: number;
  color: string;
  opacity: number;
}

interface Verdict {
  host: string;
  allowed: boolean;
  age: number;
}

interface Geometry {
  kernel: SVGPathElement;
  detour: SVGPathElement;
  kernelLen: number;
  detourLen: number;
  engineAt: number; // distance along the detour where the engine sits
}

function frameAt(t: number, g: Geometry): { dots: Dot[]; verdict: Verdict | null } {
  const dots: Dot[] = [];
  let verdict: Verdict | null = null;
  const toEngine = g.engineAt / DETOUR_SPEED;
  const first = Math.max(0, Math.floor((t - 14) / SPAWN_EVERY));
  const last = Math.floor(t / SPAWN_EVERY);

  for (let i = first; i <= last; i++) {
    const start = i * SPAWN_EVERY;
    const age = t - start;
    if (age < 0) continue;
    const conn = CONNECTIONS[i % CONNECTIONS.length];
    const decidedAt = toEngine + DWELL;

    // First packet: along the detour, held at the engine, then on or out.
    let d: number;
    let color = COLORS.inspect;
    let opacity = 1;
    if (age < toEngine) {
      d = age * DETOUR_SPEED;
    } else if (age < decidedAt) {
      d = g.engineAt;
    } else if (conn.allowed) {
      d = g.engineAt + (age - decidedAt) * DETOUR_SPEED;
      color = COLORS.fast;
    } else {
      d = g.engineAt;
      color = COLORS.stop;
      opacity = Math.max(0, 1 - (age - decidedAt) / 0.9);
    }
    if (d <= g.detourLen && opacity > 0) {
      const p = g.detour.getPointAtLength(d);
      dots.push({ key: `${i}-0`, x: p.x, y: p.y, color, opacity });
    }

    if (age >= decidedAt) {
      const since = age - decidedAt;
      if (!verdict || since < verdict.age) verdict = { host: conn.host, allowed: conn.allowed, age: since };
    }

    // The rest of an allowed connection: straight down the kernel lane.
    if (conn.allowed) {
      for (let k = 0; k < FOLLOWERS; k++) {
        const fa = age - decidedAt - k * FOLLOW_GAP;
        if (fa < 0) break;
        const fd = fa * FAST_SPEED;
        if (fd > g.kernelLen) continue;
        const p = g.kernel.getPointAtLength(fd);
        dots.push({ key: `${i}-${k + 1}`, x: p.x, y: p.y, color: COLORS.fast, opacity: 1 });
      }
    }
  }
  return { dots, verdict };
}

export function LaneHero() {
  const kernelRef = useRef<SVGPathElement>(null);
  const detourRef = useRef<SVGPathElement>(null);
  const [frame, setFrame] = useState<{ dots: Dot[]; verdict: Verdict | null }>({ dots: [], verdict: null });

  useEffect(() => {
    const kernel = kernelRef.current;
    const detour = detourRef.current;
    if (!kernel || !detour) return;

    const detourLen = detour.getTotalLength();
    // Find where the detour passes x = 500 on its lower stretch: the engine.
    let engineAt = detourLen / 2;
    for (let d = 0; d < detourLen; d += 2) {
      const p = detour.getPointAtLength(d);
      if (p.y > 200 && p.x >= 500) {
        engineAt = d;
        break;
      }
    }
    const g: Geometry = { kernel, detour, kernelLen: kernel.getTotalLength(), detourLen, engineAt };

    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (still) {
      setFrame(frameAt(9.4, g));
      return;
    }

    let raf = 0;
    const t0 = performance.now() - 6000; // start mid-stream, not on an empty road
    const tick = (now: number) => {
      setFrame(frameAt((now - t0) / 1000, g));
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  const v = frame.verdict;
  const verdictOpacity = v ? Math.max(0, Math.min(1, 1.6 - v.age)) : 0;

  return (
    <figure className="lane-hero">
      <svg viewBox="0 0 1000 300" role="img" aria-labelledby="lane-title lane-desc">
        <title id="lane-title">How Gatekeep routes packets</title>
        <desc id="lane-desc">
          The first packet of every new connection detours through the engine, which allows or blocks the connection.
          After that, the remaining packets of an allowed connection travel straight through the kernel lane.
        </desc>

        {/* Roads */}
        <path d={DETOUR_PATH} className="road" strokeWidth={40} />
        <path d={KERNEL_PATH} className="road" strokeWidth={52} />
        <path d={KERNEL_PATH} className="road-edge" transform="translate(0,-26)" />
        <path d={KERNEL_PATH} className="road-edge" transform="translate(0,26)" />
        <path ref={kernelRef} d={KERNEL_PATH} className="lane-line" />
        <path ref={detourRef} d={DETOUR_PATH} className="lane-line lane-line-detour" />

        {/* Engine booth */}
        <rect x="446" y="246" width="108" height="40" rx="5" className="booth" />
        <text x="500" y="271" textAnchor="middle" className="booth-label">
          Engine
        </text>

        {/* Labels */}
        <text x="16" y="44" className="lane-label">
          client
        </text>
        <text x="984" y="44" textAnchor="end" className="lane-label">
          server
        </text>
        <text x="420" y="44" textAnchor="middle" className="lane-label lane-label-fast">
          Kernel lane: every later packet
        </text>
        <text x="236" y="250" textAnchor="end" className="lane-label lane-label-inspect">
          First packets of a
        </text>
        <text x="236" y="270" textAnchor="end" className="lane-label lane-label-inspect">
          new connection
        </text>

        {v && (
          <g opacity={verdictOpacity} className="verdict">
            <text x="618" y="262" className={v.allowed ? "verdict-ok" : "verdict-stop"}>
              {v.host}
            </text>
            <text x="618" y="282" className={v.allowed ? "verdict-ok" : "verdict-stop"}>
              {v.allowed ? "allowed, sent to kernel lane" : "blocked, connection reset"}
            </text>
          </g>
        )}

        {frame.dots.map((d) => (
          <circle key={d.key} cx={d.x} cy={d.y} r={6} fill={d.color} opacity={d.opacity} />
        ))}
      </svg>
    </figure>
  );
}
