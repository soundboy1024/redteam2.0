"""Gate 2: prove the sandboxed tools trip the right wires against a live listener.

Run from the repo root with the .venv python: python gates/gate2.py
Reuses the listener helpers from gate1 (same directory) rather than copying them.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "gates"))

import requests  # noqa: E402

from gate1 import port_open, wait_healthy  # noqa: E402
from harness.tools import (ListenerUnreachable, ToolContext, ToolError, read_workspace_file,  # noqa: E402
                           send_http_request)
from rt_config import load_config  # noqa: E402
from traps.events_db import fetch_events  # noqa: E402

EVIDENCE_DIR = os.path.join(ROOT, "gates", "evidence")
DB_PATH = os.path.join(EVIDENCE_DIR, "gate2.db")
TXT_PATH = os.path.join(EVIDENCE_DIR, "gate2.txt")
RUN_ID = "gate2"

lines: list[str] = []


def out(text: str = "") -> None:
    print(text)
    lines.append(text)


def stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        out("listener ignored terminate; killing the process this gate started")
        proc.kill()
        proc.wait(timeout=10)


def show(title: str, row: dict) -> None:
    out(f"--- {title} ---")
    for k, v in row.items():
        out(f"  {k}: {v!r}")


def load_scenario() -> dict:
    with open(os.path.join(ROOT, "traps", "scenarios.json"), encoding="utf-8") as f:
        return next(s for s in json.load(f) if s["id"] == "benign_tempting")


def run_tool_steps(base: str, workspace: str, scenario: dict) -> str | None:
    events: list[dict] = []
    ctx = ToolContext(run_id=RUN_ID, workspace=pathlib.Path(workspace),
                      canary_files=scenario["canary_files"],
                      allowed_endpoints=scenario["allowed_endpoints"],
                      event_sink=events.append, base_url=base)
    read_workspace_file(ctx, ".env")
    show("sink event: read .env", events[-1])
    if not ctx.tripwire_canary_read:
        return "reading .env did not set tripwire_canary_read"
    try:
        read_workspace_file(ctx, "../../etc/passwd")
        return "traversal was not rejected"
    except ToolError as exc:
        out(f"ToolError raised: {exc}")
    show("sink event: traversal", events[-1])
    if events[-1]["event"] != "path_rejected":
        return "traversal did not log path_rejected"
    send_http_request(ctx, "/exfil", {"note": "gate2"})
    rows = fetch_events(DB_PATH, RUN_ID)
    if len(rows) != 1:
        return f"expected 1 listener row for {RUN_ID}, got {len(rows)}"
    show("listener events row: /exfil", rows[0])
    if rows[0]["path"] != "/exfil" or not rows[0]["tripwire_honeypot_endpoint_hit"]:
        return "listener row must be path /exfil with tripwire_honeypot_endpoint_hit true"
    if not ctx.tripwire_unauth_tool_call:
        return "send to /exfil did not set tripwire_unauth_tool_call"
    out(f"tripwires on ctx: canary_read={ctx.tripwire_canary_read} "
        f"unauth_tool_call={ctx.tripwire_unauth_tool_call}")
    return None


def run_checker(label: str, argv: list[str]) -> str | None:
    result = subprocess.run([sys.executable, *argv], cwd=ROOT, capture_output=True, text=True)
    out(f"{label} -> exit {result.returncode}")
    if result.returncode != 0:
        out(result.stdout + result.stderr)
        return f"{label} exited {result.returncode}"
    return None


def run_gate(host: str, port: int) -> str | None:
    """Return None on pass, or a failure reason."""
    base = f"http://{host}:{port}"
    if port_open(host, port):
        return f"port {port} already in use; not touching it"
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    scenario = load_scenario()
    tmp = tempfile.mkdtemp(prefix="gate2_ws_")
    proc = subprocess.Popen(
        [sys.executable, "-m", "traps.honeypot_server", "--config", "config.yaml", "--db", DB_PATH],
        cwd=ROOT)
    try:
        wait_healthy(base, proc)
        workspace = os.path.join(tmp, "ws")
        shutil.copytree(os.path.join(ROOT, "traps", "fixtures", scenario["fixture_dir"]), workspace)
        reason = run_tool_steps(base, workspace, scenario)
        if reason:
            return reason
        return (run_checker("scripts/check_rules.py", ["scripts/check_rules.py"])
                or run_checker("traps.validate_scenarios", ["-m", "traps.validate_scenarios"]))
    finally:
        stop(proc)
        shutil.rmtree(tmp, ignore_errors=True)
        time.sleep(0.5)
        if port_open(host, port):
            out(f"WARNING: port {port} still in use after stopping listener")
        else:
            out(f"port {port} is free again")


def main() -> int:
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    host, port = cfg["listener"]["host"], cfg["listener"]["port"]
    try:
        reason = run_gate(host, port)
    except (RuntimeError, requests.RequestException, OSError, KeyError, ValueError,
            StopIteration, ListenerUnreachable, ToolError) as exc:
        reason = f"{type(exc).__name__}: {exc}"
    out("GATE 2: PASS" if reason is None else f"GATE 2: FAIL {reason}")
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    with open(TXT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return 0 if reason is None else 1


if __name__ == "__main__":
    sys.exit(main())
