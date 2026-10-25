#!/usr/bin/env python3
"""Records a real demo session for the website's replay mode.

Runs each scenario against the running lab (docker compose up -d --build),
while sampling the engine's stats, the kernel's fast/slow path counters and
the policy every 200 ms. Decisions come from the engine's own JSON log.
Writes web/public/replay.json.

    python3 scripts/record.py
"""

import json
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "http://127.0.0.1:8080"
OUT = ROOT / "web" / "public" / "replay.json"


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read() or "null")
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or "null")


def compose(*args, timeout=60):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def client(cmd, timeout=60):
    """Runs a shell command in the client container. Returns (exit code, output)."""
    r = compose("exec", "-T", "client", "sh", "-c", cmd, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def kernel_counters():
    out = compose("exec", "-T", "firewall", "nft", "list", "chain", "inet", "gatekeep", "forward").stdout
    counts = {}
    for line in out.splitlines():
        if "packets" not in line:
            continue
        words = line.split()
        n = int(words[words.index("packets") + 1])
        if 'comment "fast path' in line:
            counts["fast"] = n
        elif 'comment "slow path' in line:
            counts["slow"] = n
        elif "@banned" in line:
            counts["banned_drops"] = n
    return counts


T0 = time.time()


def now():
    return round(time.time() - T0, 3)


frames = []
policies = []
stop = threading.Event()


def sampler():
    while not stop.is_set():
        t = now()
        stats = api("GET", "/stats")
        frame = {
            "t": t,
            "packets_inspected": stats["packets_inspected"],
            "new_flows": stats["new_flows"],
            "pending_flows": stats["pending_flows"],
            "active_bans": stats["active_bans"],
            "decisions": stats["decisions"],
            "kernel": kernel_counters(),
            "bans": api("GET", "/bans"),
        }
        frames.append(frame)
        snapshot_policy()
        stop.wait(0.2)


policy_lock = threading.Lock()


def snapshot_policy():
    with policy_lock:
        t = now()
        policy = api("GET", "/policy")
        for r in policy["rules"]:
            r.pop("hits", None)
        if not policies or policies[-1]["policy"] != policy:
            policies.append({"t": t, "policy": policy})


def traffic(label, cmd, display=None, timeout=60, outcome=None):
    pause(0.8)
    t0 = now()
    code, out = client(cmd, timeout=timeout)
    return {
        "kind": "traffic",
        "label": label,
        "command": display or cmd,
        "outcome": outcome or ("allowed" if code == 0 else "blocked"),
        "output": out[-600:],
        "t0": t0,
        "t1": now(),
    }


def call(label, method, path, body=None):
    pause(0.8)
    t0 = now()
    resp = api(method, path, body)
    snapshot_policy()
    shown = f"{method} {path}" + (f" {json.dumps(body)}" if body is not None else "")
    return {"kind": "api", "label": label, "command": shown, "response": resp, "t0": t0, "t1": now()}


def pause(seconds=1.5):
    time.sleep(seconds)


CURL = "curl -sS -m 3"

SCENARIOS = [
    {
        "id": "web",
        "title": "Open the web server",
        "summary": "Plain HTTP to port 80. The allow-web rule matches, the first request is read (Host: 10.10.2.10), and the connection moves to the fast path.",
        "steps": lambda: [traffic("Request the home page", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/")],
    },
    {
        "id": "tls-allowed",
        "title": "Visit shop.test over HTTPS",
        "summary": "The engine waits for the TLS ClientHello, reads the server name (SNI) shop.test, finds it isn't blocked, and hands the connection to the kernel.",
        "steps": lambda: [traffic("HTTPS to shop.test", f"{CURL} -k --resolve shop.test:443:10.10.2.10 https://shop.test/", "curl https://shop.test/")],
    },
    {
        "id": "tls-blocked",
        "title": "Visit evil.test over HTTPS",
        "summary": "The traffic is encrypted, but the ClientHello names the site in plain text. evil.test is on the blocklist, so the connection is reset.",
        "steps": lambda: [traffic("HTTPS to evil.test", f"{CURL} -k --resolve evil.test:443:10.10.2.10 https://evil.test/", "curl https://evil.test/")],
    },
    {
        "id": "tls-other-port",
        "title": "Hide evil.test on port 8443",
        "summary": "Moving to a non-standard port doesn't help: TLS is recognised by its first bytes, not by the port number. Subdomains of a blocked domain are blocked too.",
        "steps": lambda: [traffic("HTTPS to cdn.evil.test:8443", f"{CURL} -k --resolve cdn.evil.test:8443:10.10.2.10 https://cdn.evil.test:8443/", "curl https://cdn.evil.test:8443/")],
    },
    {
        "id": "http-host",
        "title": "Reach tracker.test over plain HTTP",
        "summary": "For unencrypted HTTP the engine reads the Host header of the first request.",
        "steps": lambda: [traffic("HTTP with Host: tracker.test", f'{CURL} -H "Host: tracker.test" http://10.10.2.10/', "curl -H 'Host: tracker.test' http://10.10.2.10/")],
    },
    {
        "id": "dns",
        "title": "Look up names over DNS",
        "summary": "DNS queries are checked one by one and never offloaded. A query for a subdomain of a blocked domain is refused.",
        "steps": lambda: [
            traffic("Look up shop.test", "dig +short +time=2 +tries=1 @10.10.2.10 shop.test | grep -qx 10.10.2.10", "dig shop.test"),
            traffic("Look up ads.tracker.test", "dig +short +time=2 +tries=1 @10.10.2.10 ads.tracker.test | grep -qx 10.10.2.10", "dig ads.tracker.test"),
        ],
    },
    {
        "id": "ports",
        "title": "Try telnet and SSH",
        "summary": "Telnet matches a reject rule and gets an immediate TCP reset. SSH matches no rule, so the default policy drops it silently.",
        "steps": lambda: [
            traffic("Telnet to port 23", "nc -z -w 2 10.10.2.10 23", "nc 10.10.2.10 23"),
            traffic("SSH to port 22", "nc -z -w 2 10.10.2.10 22", "nc 10.10.2.10 22"),
        ],
    },
    {
        "id": "quarantine",
        "title": "Connect from a quarantined host",
        "summary": "Traffic from 10.10.1.66 matches the first rule and is dropped, whatever it is.",
        "steps": lambda: [traffic("HTTP from 10.10.1.66", f"{CURL} --interface 10.10.1.66 http://10.10.2.10/", "curl --interface 10.10.1.66 http://10.10.2.10/")],
    },
    {
        "id": "hot-rule",
        "title": "Change the rules while it runs",
        "summary": "A rule added through the API applies immediately, including to connections that were already open: cached verdicts are flushed and re-checked.",
        "steps": lambda: [
            call("Add a rule at the top", "POST", "/rules?position=0", {"id": "maintenance", "action": "reject", "proto": "tcp", "dst_ports": "80"}),
            traffic("Request the home page", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/"),
            call("Remove the rule", "DELETE", "/rules/maintenance"),
            traffic("Request the home page again", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/"),
        ],
    },
    {
        "id": "flood",
        "title": "Launch a SYN flood",
        "summary": "3,000 connection attempts at 2,000 per second. The token bucket lets a burst through, refuses the rest, and after 200 refusals bans the source in the kernel.",
        "steps": lambda: [
            traffic("3,000 SYNs at 2,000/s", "hping3 -S -p 80 -i u500 -c 3000 -q 10.10.2.10 >/dev/null 2>&1; true", "hping3 -S -p 80 -i u500 -c 3000 10.10.2.10", outcome="sent"),
            traffic("Request the home page while banned", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/"),
            call("Lift the ban", "DELETE", "/bans/10.10.1.10"),
            traffic("Request the home page again", f"{CURL} http://10.10.2.10/", "curl http://10.10.2.10/"),
        ],
    },
    {
        "id": "bulk",
        "title": "Download at full speed",
        "summary": "A 3-second iperf3 transfer. Only the first packets of each connection reach the engine; the kernel forwards the rest.",
        "steps": lambda: [traffic("3-second iperf3 transfer", "iperf3 -c 10.10.2.10 -t 3 -f g | grep receiver", "iperf3 -c 10.10.2.10 -t 3")],
    },
]


def main():
    global T0
    api("POST", "/policy/reload")
    for ip in ("10.10.1.10", "10.10.1.66"):
        api("DELETE", f"/bans/{ip}")
    time.sleep(1)

    T0 = time.time()
    since = datetime.fromtimestamp(T0, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    pause(1)

    scenarios = []
    for s in SCENARIOS:
        print(f"  {s['title']}")
        t0 = now()
        steps = s["steps"]()
        pause()
        scenarios.append({"id": s["id"], "title": s["title"], "summary": s["summary"], "t0": t0, "t1": now(), "steps": steps})

    stop.set()
    thread.join()

    events = []
    logs = compose("logs", "--no-color", "--no-log-prefix", "--since", since, "firewall").stdout
    for line in logs.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        e = json.loads(line)
        wall = datetime.fromisoformat(e["ts"].replace("Z", "+00:00")).timestamp()
        e["t"] = round(wall - T0, 3)
        if e["t"] >= 0:
            events.append(e)

    replay = {
        "recorded_at": datetime.fromtimestamp(T0, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration": now(),
        "scenarios": scenarios,
        "events": events,
        "frames": frames,
        "policies": policies,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(replay, separators=(",", ":")))
    print(f"wrote {OUT.relative_to(ROOT)}: {len(scenarios)} scenarios, {len(events)} decisions, {len(frames)} frames, {OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
