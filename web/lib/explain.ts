// Plain-language wording for the engine's decisions, used by live mode.
import { reasonText, type Decision } from "./replay";

export function explain(d: Decision): string {
  if (d.rule === "default") return "No rule matched, so the default policy dropped it.";
  switch (d.reason) {
    case "policy":
      return `Matched rule ${d.rule}.`;
    case "inspected":
      return `Rule ${d.rule} allowed it, and the first payload was clean.`;
    case "domain_blocked":
      return "The name is on the blocklist.";
    case "rate_limit_ban":
      return `Over the new-connection limit too often: source banned for ${d.ban_seconds ?? 30} seconds.`;
    default:
      return `${reasonText[d.reason] ?? d.reason}.`;
  }
}

export function clock(ts: string): string {
  return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
}
