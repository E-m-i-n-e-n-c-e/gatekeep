import type { Metadata } from "next";

import { LiveReplay } from "@/components/LiveReplay";
import { loadReplay } from "@/lib/load";

export const metadata: Metadata = {
  title: "Demo: Gatekeep",
  description: "A recorded session of the Gatekeep firewall: real commands, real decisions, real counters.",
};

export default function LivePage() {
  const { recorded_at } = loadReplay();
  const date = new Date(recorded_at).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
  return (
    <div className="wrap live">
      <header className="live-head">
        <h1>Demo</h1>
        <p>
          A real session recorded on {date}: commands sent from a client container through the firewall to a server,
          with every decision the engine made and the kernel&apos;s packet counters. Gatekeep needs a Linux kernel to
          run, so this page plays the recording back. To run it live, see the <a href="/docs#run-it">setup guide</a>.
        </p>
      </header>
      <LiveReplay />
    </div>
  );
}
