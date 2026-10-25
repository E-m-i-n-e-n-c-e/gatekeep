// Outcome icons. Every outcome colour ships with one of these and a word.

export function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <path d="M2.5 7.5l3 3 6-7" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function CrossIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <path d="M3 3l8 8M11 3l-8 8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export function EyeIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <path d="M1 7s2.2-4 6-4 6 4 6 4-2.2 4-6 4-6-4-6-4z" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="7" cy="7" r="1.8" fill="currentColor" />
    </svg>
  );
}

export function DotIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <circle cx="7" cy="7" r="3" fill="currentColor" />
    </svg>
  );
}

export function OutcomeTag({ outcome }: { outcome: "allowed" | "blocked" | "sent" | "running" }) {
  const icon = outcome === "allowed" ? <CheckIcon /> : outcome === "blocked" ? <CrossIcon /> : <DotIcon />;
  const word = { allowed: "Allowed", blocked: "Blocked", sent: "Sent", running: "Running" }[outcome];
  return (
    <span className={`tag tag-${outcome}`}>
      {icon}
      {word}
    </span>
  );
}
