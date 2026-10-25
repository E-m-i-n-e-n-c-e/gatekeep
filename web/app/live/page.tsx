import type { Metadata } from "next";

import { LiveConsole } from "@/components/LiveConsole";

export const metadata: Metadata = {
  title: "Live: Gatekeep",
  description: "Drive a running Gatekeep firewall: send traffic, change rules and watch its decisions as they happen.",
};

export default function LivePage() {
  return (
    <div className="wrap live">
      <header className="live-head">
        <h1>Live</h1>
        <p>
          Connected to a running firewall, everything here is happening now: run a scenario to send real traffic through
          it, change its rules, and watch its decisions and packet counters update.
        </p>
      </header>
      <LiveConsole />
    </div>
  );
}
