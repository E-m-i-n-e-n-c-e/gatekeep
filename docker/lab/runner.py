"""Scenario runner for live mode. Runs inside the client container.

    GET  /health
    GET  /scenarios           the list, without the raw shell commands
    POST /run/<scenario id>   runs it; streams one JSON line per step event

Only the fixed scenarios in scenarios.py can run, one at a time. Browsers may
call it only from pages on localhost (plus any origins in GATEKEEP_CORS_ORIGINS);
compose publishes the port on 127.0.0.1 only.
"""

import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scenarios import SCENARIOS

FIREWALL_API = os.environ.get("GATEKEEP_API", "http://10.10.1.2:8080")
LOCAL_ORIGIN = re.compile(r"^https?://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?$")
EXTRA_ORIGINS = {o.strip() for o in os.environ.get("GATEKEEP_CORS_ORIGINS", "").split(",") if o.strip()}
STEP_GAP = 0.8  # seconds between steps, so each one can be followed

BY_ID = {s["id"]: s for s in SCENARIOS}
busy = threading.Lock()


def origin_allowed(origin):
    return bool(LOCAL_ORIGIN.match(origin)) or origin in EXTRA_ORIGINS


def run_traffic(step):
    proc = subprocess.run(["sh", "-c", step["cmd"]], capture_output=True, text=True, timeout=60)
    out = (proc.stdout + proc.stderr).strip()
    outcome = step["outcome"] or ("allowed" if proc.returncode == 0 else "blocked")
    return {"outcome": outcome, "output": out[-600:]}


def call_api(step):
    data = json.dumps(step["body"]).encode() if step["body"] is not None else None
    req = urllib.request.Request(FIREWALL_API + step["path"], data=data, method=step["method"])
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return {"status": resp.status, "response": json.loads(resp.read() or b"null")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "response": json.loads(e.read() or b"null")}


def public_step(step):
    if step["kind"] == "api":
        body = f" {json.dumps(step['body'])}" if step["body"] is not None else ""
        return {"kind": "api", "label": step["label"], "command": f"{step['method']} {step['path']}{body}"}
    return {"kind": "traffic", "label": step["label"], "command": step["command"]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[runner] {self.address_string()} {fmt % args}", flush=True)

    def origin(self):
        return self.headers.get("Origin", "")

    def cors(self):
        if origin_allowed(self.origin()):
            self.send_header("Access-Control-Allow-Origin", self.origin())
            self.send_header("Vary", "Origin")

    def json_reply(self, body, status=200):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        if not origin_allowed(self.origin()):
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(204)
        self.cors()
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            return self.json_reply({"status": "ok", "busy": busy.locked()})
        if self.path == "/scenarios":
            return self.json_reply([
                {"id": s["id"], "title": s["title"], "summary": s["summary"], "steps": [public_step(st) for st in s["steps"]]}
                for s in SCENARIOS
            ])
        self.json_reply({"error": "not found"}, 404)

    def do_POST(self):
        # A page on another site can still send a simple POST; refuse it.
        if self.origin() and not origin_allowed(self.origin()):
            return self.json_reply({"error": "origin not allowed"}, 403)
        m = re.fullmatch(r"/run/([a-z0-9-]+)", self.path)
        scenario = BY_ID.get(m.group(1)) if m else None
        if not scenario:
            return self.json_reply({"error": "no such scenario"}, 404)
        if not busy.acquire(blocking=False):
            return self.json_reply({"error": "another scenario is running"}, 409)
        try:
            self.send_response(200)
            self.cors()
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.stream(scenario)
        finally:
            busy.release()

    def emit(self, event):
        self.wfile.write((json.dumps(event) + "\n").encode())
        self.wfile.flush()

    def stream(self, scenario):
        try:
            self.emit({"event": "start", "id": scenario["id"], "t": time.time()})
            for i, step in enumerate(scenario["steps"]):
                time.sleep(STEP_GAP)
                t0 = time.time()
                self.emit({"event": "step-start", "index": i, "t0": t0})
                result = call_api(step) if step["kind"] == "api" else run_traffic(step)
                self.emit({"event": "step-done", "index": i, **public_step(step), **result, "t0": t0, "t1": time.time()})
            self.emit({"event": "end", "t": time.time()})
        except (BrokenPipeError, ConnectionResetError):
            pass  # the page went away; the scenario still finished its current step


if __name__ == "__main__":
    print("[runner] scenario runner on :8081", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
