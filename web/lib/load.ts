// Build-time access to the recorded session (server components only).
import { readFileSync } from "fs";
import path from "path";

import type { Replay } from "./replay";

export function loadReplay(): Replay {
  return JSON.parse(readFileSync(path.join(process.cwd(), "public", "replay.json"), "utf8"));
}

/** Packets handled by the kernel vs the engine during the bulk-transfer scenario. */
export function bulkSplit(replay: Replay) {
  const bulk = replay.scenarios.find((s) => s.id === "bulk");
  if (!bulk) throw new Error("replay.json has no bulk scenario");
  const before = [...replay.frames].reverse().find((f) => f.t <= bulk.t0) ?? replay.frames[0];
  const after = replay.frames.find((f) => f.t >= bulk.t1) ?? replay.frames[replay.frames.length - 1];
  const step = bulk.steps[0];
  const gbps = step.kind === "traffic" ? Number(step.output.match(/([\d.]+) Gbits\/sec/)?.[1] ?? 0) : 0;
  return {
    kernel: (after.kernel.fast ?? 0) - (before.kernel.fast ?? 0),
    engine: after.packets_inspected - before.packets_inspected,
    gbps,
  };
}
