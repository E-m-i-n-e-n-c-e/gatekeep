"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/", label: "How it works" },
  { href: "/demo", label: "Demo" },
  { href: "/live", label: "Live" },
  { href: "/docs", label: "Docs" },
];

export function SiteHeader({ github }: { github: string }) {
  const path = usePathname();
  return (
    <header className="site-header">
      <div className="wrap">
        <Link href="/" className="wordmark">
          Gatekeep
        </Link>
        <nav className="nav" aria-label="Main">
          {links.map((l) => (
            <Link key={l.href} href={l.href} aria-current={path === l.href ? "page" : undefined}>
              {l.label}
            </Link>
          ))}
          <a href={github}>GitHub</a>
        </nav>
      </div>
    </header>
  );
}
