"use client";

import { useState } from "react";

// Small-packet forwarding rate, from scripts/bench.sh on Docker Desktop
// (4 parallel UDP streams of 64-byte payloads). "Kernel alone" is drawn as a
// reference line, not a bar: it is the ceiling the two modes are measured against.

const KERNEL_ALONE = 1445;
const BARS = [
  { id: "fast", label: "Gatekeep, fast path", value: 1376, color: "var(--fast)", note: "95% of kernel alone" },
  { id: "slow", label: "Every packet to the engine", value: 180, color: "var(--inspect)", note: "12% of kernel alone" },
];

const W = 640;
const LABEL_W = 0;
const BAR_H = 34;
const GAP = 22;
const TOP = 34;
const MAX = 1600;
const x = (v: number) => LABEL_W + (v / MAX) * (W - LABEL_W);

export function BenchChart() {
  const [hover, setHover] = useState<string | null>(null);
  const height = TOP + BARS.length * (BAR_H + GAP) + 24;
  const ticks = [0, 400, 800, 1200, 1600];

  return (
    <figure className="bench">
      <div className="bench-plot">
        <svg viewBox={`0 0 ${W} ${height}`} role="img" aria-label="Packets forwarded per second, in thousands">
          {ticks.map((t) => (
            <g key={t}>
              <line x1={x(t)} x2={x(t)} y1={TOP - 8} y2={height - 22} className="grid" />
              <text x={x(t)} y={height - 4} textAnchor={t === 0 ? "start" : t === MAX ? "end" : "middle"} className="axis">
                {t === 0 ? "0" : `${t / 1000}M`}
              </text>
            </g>
          ))}

          {BARS.map((b, i) => {
            const y = TOP + i * (BAR_H + GAP);
            const w = x(b.value) - x(0);
            return (
              <g
                key={b.id}
                onMouseEnter={() => setHover(b.id)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(b.id)}
                onBlur={() => setHover(null)}
                tabIndex={0}
                aria-label={`${b.label}: ${b.value.toLocaleString("en-US")} thousand packets per second, ${b.note}`}
              >
                <rect x={0} y={y - 6} width={W} height={BAR_H + 12} fill="transparent" />
                <path
                  d={`M0,${y} H${w - 4} a4,4 0 0 1 4,4 V${y + BAR_H - 4} a4,4 0 0 1 -4,4 H0 Z`}
                  fill={b.color}
                  opacity={hover && hover !== b.id ? 0.45 : 1}
                />
                <text
                  x={w > 200 ? w - 10 : w + 10}
                  y={y + BAR_H / 2 + 5}
                  textAnchor={w > 200 ? "end" : "start"}
                  className={w > 200 ? "bar-value bar-value-in" : "bar-value"}
                >
                  {b.value.toLocaleString("en-US")}k/s
                </text>
              </g>
            );
          })}

          <line x1={x(KERNEL_ALONE)} x2={x(KERNEL_ALONE)} y1={TOP - 14} y2={height - 22} className="ref-line" />
          <text x={x(KERNEL_ALONE) - 6} y={TOP - 18} textAnchor="end" className="ref-label">
            Kernel alone, no engine: 1,445k/s
          </text>
        </svg>

        {hover && (
          <div className="bench-tip" role="status">
            {(() => {
              const b = BARS.find((bar) => bar.id === hover)!;
              return (
                <>
                  <strong>{b.label}</strong>
                  <span>{b.value.toLocaleString("en-US")}k packets/s</span>
                  <span>{b.note}</span>
                </>
              );
            })()}
          </div>
        )}
      </div>

      <ul className="bench-legend" aria-hidden="true">
        {BARS.map((b) => (
          <li key={b.id}>
            <span className="swatch" style={{ background: b.color }} />
            {b.label}
          </li>
        ))}
      </ul>

      <details className="bench-table">
        <summary>Show as a table</summary>
        <table>
          <thead>
            <tr>
              <th scope="col">Mode</th>
              <th scope="col">64-byte packets/s</th>
              <th scope="col">Of kernel alone</th>
              <th scope="col">Engine CPU on a TCP stream</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Kernel alone (engine bypassed)</td>
              <td>1,445,000</td>
              <td>100%</td>
              <td>n/a</td>
            </tr>
            <tr>
              <td>Gatekeep, fast path</td>
              <td>1,376,000</td>
              <td>95%</td>
              <td>about 0%</td>
            </tr>
            <tr>
              <td>Every packet to the engine</td>
              <td>180,000</td>
              <td>12%</td>
              <td>80%</td>
            </tr>
          </tbody>
        </table>
      </details>
    </figure>
  );
}
