// Where live mode finds the firewall's control API and the lab's scenario
// runner. Defaults to a lab on this computer; set these at build time to point
// the site at a hosted backend instead.
export const API_URL = (process.env.NEXT_PUBLIC_GATEKEEP_API ?? "http://127.0.0.1:8080").replace(/\/$/, "");
export const RUNNER_URL = (process.env.NEXT_PUBLIC_GATEKEEP_RUNNER ?? "http://127.0.0.1:8081").replace(/\/$/, "");

const CONFIGURED = Boolean(process.env.NEXT_PUBLIC_GATEKEEP_API);

/**
 * Whether this page may try to reach the backend. A public page reaching for
 * 127.0.0.1 triggers the browser's local-network permission prompt, so the
 * public site only does it when a backend address was configured.
 */
export function canConnect(): boolean {
  const host = window.location.hostname;
  return host === "localhost" || host === "127.0.0.1" || CONFIGURED;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export async function call<T>(base: string, method: string, path: string, body?: unknown, timeoutMs = 4000): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(base + path, {
      method,
      signal: ctrl.signal,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    if (!res.ok) throw new ApiError((data && data.error) || `HTTP ${res.status}`, res.status);
    return data as T;
  } finally {
    clearTimeout(timer);
  }
}

/** True if the firewall's API answers within the timeout. */
export async function firewallReachable(timeoutMs = 1200): Promise<boolean> {
  try {
    await call(API_URL, "GET", "/health", undefined, timeoutMs);
    return true;
  } catch {
    return false;
  }
}
