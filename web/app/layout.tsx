import type { Metadata } from "next";
import { Barlow, Barlow_Semi_Condensed, JetBrains_Mono } from "next/font/google";

import { SiteHeader } from "@/components/SiteHeader";
import { GITHUB } from "@/lib/site";

import "./globals.css";

const barlow = Barlow({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-barlow" });
const barlowSc = Barlow_Semi_Condensed({
  subsets: ["latin"],
  weight: ["500", "600", "700"],
  variable: "--font-barlow-sc",
});
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "Gatekeep: a stateful firewall with a kernel fast path",
  description:
    "A Linux firewall in C++ that inspects the first packets of every connection in userspace, then caches the verdict in the kernel.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${barlow.variable} ${barlowSc.variable} ${mono.variable}`}>
      <body>
        <SiteHeader github={GITHUB} />
        <main>{children}</main>
        <footer className="site-footer">
          <div className="wrap">
            <span>
              Gatekeep, built by <a href="https://akhil-k.in">Akhil K</a>.
            </span>
            <span>
              C++17, Linux nftables and NFQUEUE. <a href={GITHUB}>Source on GitHub</a>
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}
