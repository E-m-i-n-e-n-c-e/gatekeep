#!/usr/bin/env python3
"""Records a real demo session for the website's replay (Demo page).

Runs every scenario through the scenario runner (the same one the website's
live mode uses), while sampling the engine's stats, the kernel's fast/slow
path counters, bans and the policy every 200 ms. Needs the lab running
(docker compose up -d --build). Writes web/public/replay.json.

    python3 scripts/record.py
"""

import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "http://127.0.0.1:8080"
RUNNER = "http://127.0.0.1:8081"
OUT = ROOT / "web" / "public" / "replay.json"
SCENARIO_GAP = 1.5  # seconds of quiet after each scenario


def request(base, method, path, body=None, timeout=5):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        return e


def api(method, path, body=None):
    with request(API, method, path, body) as resp:
        return json.loads(resp.read() or b"null")


T0 = time.time()
frames = []
policies = []
policy_lock = threading.Lock()
stop = threading.Event()


def now(wall=None):
    return round((wall or time.time()) - T0, 3)


def snapshot_policy():
    with policy_lock:
        t = now()
        policy = api("GET", "/policy")
        for r in policy["rules"]:
            r.pop("hits", None)
        if not policies or policies[-1]["policy"] != policy:
            policies.append({"t": t, "policy": policy})


def sampler():
    while not stop.is_set():
        t = now()
        stats = api("GET", "/stats")
        frames.append({
            "t": t,
            "packets_inspected": stats["packets_inspected"],
            "new_flows": stats["new_flows"],
            "pending_flows": stats["pending_flows"],
            "active_bans": stats["active_bans"],
            "decisions": stats["decisions"],
            "kernel": api("GET", "/kernel"),
            "bans": api("GET", "/bans"),
        })
        snapshot_policy()
        stop.wait(0.2)


def run_scenario(scenario_id):
    """Runs one scenario through the runner; returns its steps with session times."""
    steps = []
    with request(RUNNER, "POST", f"/run/{scenario_id}", timeout=120) as resp:
        for line in resp:
            event = json.loads(line)
            if event["event"] != "step-done":
                continue
            step = {k: v for k, v in event.items() if k not in ("event", "index")}
            step["t0"], step["t1"] = now(step["t0"]), now(step["t1"])
            if step["kind"] == "api":
                snapshot_policy()
            steps.append(step)
    return steps


def main():
    global T0
    with request(RUNNER, "GET", "/scenarios") as resp:
        scenarios = json.loads(resp.read())
    api("POST", "/policy/reload")
    for ip in ("10.10.1.10", "10.10.1.66"):
        api("DELETE", f"/bans/{ip}")
    time.sleep(1)

    T0 = time.time()
    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    time.sleep(1)

    recorded = []
    for s in scenarios:
        print(f"  {s['title']}")
        t0 = now()
        steps = run_scenario(s["id"])
        time.sleep(SCENARIO_GAP)
        recorded.append({"id": s["id"], "title": s["title"], "summary": s["summary"], "t0": t0, "t1": now(), "steps": steps})

    stop.set()
    thread.join()

    events = []
    for e in api("GET", "/events?limit=256"):
        wall = datetime.fromisoformat(e["ts"].replace("Z", "+00:00")).timestamp()
        e["t"] = now(wall)
        if e["t"] >= 0:
            events.append(e)

    replay = {
        "recorded_at": datetime.fromtimestamp(T0, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration": now(),
        "scenarios": recorded,
        "events": events,
        "frames": frames,
        "policies": policies,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(replay, separators=(",", ":")))
    print(f"wrote {OUT.relative_to(ROOT)}: {len(recorded)} scenarios, {len(events)} decisions, "
          f"{len(frames)} frames, {OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
