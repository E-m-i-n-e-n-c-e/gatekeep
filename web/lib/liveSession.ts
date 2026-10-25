// The live-mode session: the scenario being run, past results, the run-all
// loop and the counter baseline. It lives at module level, not in a page
// component, so switching tabs doesn't throw it away while a scenario is
// still running in the lab. (A full page reload does reset it; the runner's
// busy flag covers that case.)
import { useSyncExternalStore } from "react";

import { RUNNER_URL } from "./endpoints";

export interface ScenarioInfo {
  id: string;
  title: string;
  summary: string;
  steps: { kind: "traffic" | "api"; label: string; command: string }[];
}

export interface RunStep {
  kind: "traffic" | "api";
  label: string;
  command: string;
  state: "upcoming" | "running" | "done";
  outcome?: "allowed" | "blocked" | "sent";
  output?: string;
  status?: number;
}

export interface Run {
  scenario: ScenarioInfo;
  steps: RunStep[];
  finished: boolean;
  error?: string;
}

export interface Baseline {
  fast: number;
  banned_drops: number;
  inspected: number;
}

export interface Session {
  run: Run | null;
  results: Record<string, RunStep[]>;
  playingAll: boolean;
  stopRequested: boolean;
  baseline: Baseline | null;
  stepsDone: number; // bumps after every finished step, so the page can refresh
}

let state: Session = { run: null, results: {}, playingAll: false, stopRequested: false, baseline: null, stepsDone: 0 };
const listeners = new Set<() => void>();

function set(patch: Partial<Session> | ((s: Session) => Partial<Session>)) {
  state = { ...state, ...(typeof patch === "function" ? patch(state) : patch) };
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useSession(): Session {
  return useSyncExternalStore(subscribe, () => state, () => state);
}

export function setBaseline(b: Baseline) {
  set({ baseline: b });
}

export function initBaseline(b: Baseline) {
  if (!state.baseline) set({ baseline: b });
}

function updateRun(id: string, fn: (r: Run) => Partial<Run>) {
  set((s) => (s.run && s.run.scenario.id === id ? { run: { ...s.run, ...fn(s.run) } } : {}));
}

/** Runs one scenario through the runner, streaming each step's result into the session. */
export async function runScenario(s: ScenarioInfo): Promise<void> {
  const fail = (error: string) => updateRun(s.id, () => ({ finished: true, error }));
  set({ run: { scenario: s, steps: s.steps.map((st) => ({ ...st, state: "upcoming" })), finished: false } });

  try {
    const res = await fetch(`${RUNNER_URL}/run/${s.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    if (res.status === 409) return fail("Another scenario is still running in the lab. Wait for it to finish.");
    if (!res.ok || !res.body) return fail(`The scenario runner answered HTTP ${res.status}.`);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const event = JSON.parse(buffer.slice(0, nl));
        buffer = buffer.slice(nl + 1);
        if (event.event === "step-start") {
          updateRun(s.id, (r) => ({ steps: r.steps.map((st, i) => (i === event.index ? { ...st, state: "running" } : st)) }));
        } else if (event.event === "step-done") {
          updateRun(s.id, (r) => ({
            steps: r.steps.map((st, i) =>
              i === event.index ? { ...st, state: "done", outcome: event.outcome, output: event.output, status: event.status } : st,
            ),
          }));
          set((cur) => ({ stepsDone: cur.stepsDone + 1 }));
        }
      }
    }
    updateRun(s.id, () => ({ finished: true }));
    set((cur) => (cur.run && cur.run.scenario.id === s.id ? { results: { ...cur.results, [s.id]: cur.run.steps } } : {}));
  } catch {
    fail(`Lost the scenario runner at ${RUNNER_URL}.`);
  }
}

/** Runs every scenario in order. A stop request lets the current one finish first. */
export async function runAll(scenarios: ScenarioInfo[]): Promise<void> {
  if (state.playingAll) return;
  set({ playingAll: true, stopRequested: false });
  for (const s of scenarios) {
    if (state.stopRequested) break;
    await runScenario(s);
    if (state.run?.error) break;
    if (!state.stopRequested) await new Promise((r) => setTimeout(r, 1200));
  }
  set({ playingAll: false, stopRequested: false });
}

export function requestStop() {
  set({ stopRequested: true });
}
