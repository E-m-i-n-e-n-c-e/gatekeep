// Shape of public/replay.json, written by scripts/record.py from a real run of the lab.

export type Verdict =
  | "allow_flow"
  | "allow_packet"
  | "drop_flow"
  | "drop_packet"
  | "reject_flow"
  | "reject_packet";

export interface Decision {
  t: number;
  ts: string;
  verdict: Verdict;
  reason: string;
  proto: string;
  src: string;
  dst: string;
  src_port?: number;
  dst_port?: number;
  rule?: string;
  app?: string;
  host?: string;
  ban_seconds?: number;
}

export interface Frame {
  t: number;
  packets_inspected: number;
  new_flows: number;
  pending_flows: number;
  active_bans: number;
  decisions: Record<string, number>;
  kernel: { fast?: number; slow?: number; banned_drops?: number };
  bans: { ip: string; expires_in_s: number }[];
}

export interface Rule {
  id: string;
  action: "allow" | "drop" | "reject";
  proto?: string;
  src?: string;
  dst?: string;
  dst_ports?: string;
}

export interface Policy {
  default_action: string;
  rules: Rule[];
  blocked_domains: string[];
  rate_limit: { new_flows_per_sec: number; burst: number; ban_after: number; ban_seconds: number };
  max_inspect_packets: number;
}

export interface TrafficStep {
  kind: "traffic";
  label: string;
  command: string;
  outcome: "allowed" | "blocked" | "sent";
  output: string;
  t0: number;
  t1: number;
}

export interface ApiStep {
  kind: "api";
  label: string;
  command: string;
  response: unknown;
  t0: number;
  t1: number;
}

export type Step = TrafficStep | ApiStep;

export interface Scenario {
  id: string;
  title: string;
  summary: string;
  t0: number;
  t1: number;
  steps: Step[];
}

export interface Replay {
  recorded_at: string;
  duration: number;
  scenarios: Scenario[];
  events: Decision[];
  frames: Frame[];
  policies: { t: number; policy: Policy }[];
}

/** Last item whose `t` is <= time (items sorted by t), or the first item. */
export function at<T extends { t: number }>(items: T[], time: number): T {
  let lo = 0;
  let hi = items.length - 1;
  let best = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (items[mid].t <= time) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return items[best];
}

/** How a decision reads to a person: allowed, blocked, or still being inspected. */
export function outcomeOf(v: Verdict): "allowed" | "blocked" {
  return v.startsWith("allow") ? "allowed" : "blocked";
}

export const verdictText: Record<Verdict, string> = {
  allow_flow: "Allowed, handed to kernel",
  allow_packet: "Allowed this packet",
  drop_flow: "Dropped",
  drop_packet: "Dropped this packet",
  reject_flow: "Reset",
  reject_packet: "Refused",
};

export const reasonText: Record<string, string> = {
  inspected: "read the first payload",
  policy: "matched a rule",
  domain_blocked: "blocked domain",
  rate_limit_ban: "flood, source banned",
  rate_limited: "over the rate limit",
  banned: "source is banned",
  inspect_limit: "no payload in time",
};

export const fmt = (n: number) => n.toLocaleString("en-US");
