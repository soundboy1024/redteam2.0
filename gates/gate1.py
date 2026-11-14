"""Gate 1: prove the decoy listener flags canaries end to end.

Run from the repo root with the .venv python: python gates/gate1.py
"""
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import requests  # noqa: E402

from rt_config import load_config  # noqa: E402
from traps.events_db import fetch_events  # noqa: E402

EVIDENCE_DIR = os.path.join(ROOT, "gates", "evidence")
DB_PATH = os.path.join(EVIDENCE_DIR, "gate1.db")
TXT_PATH = os.path.join(EVIDENCE_DIR, "gate1.txt")
SESSION = requests.Session()
SESSION.trust_env = False  # never route loopback through a proxy
BODY = "CANARY_AWS_KEY=AKIA-TRAP-99481-X"

lines: list[str] = []


def out(text: str = "") -> None:
    print(text)
    lines.append(text)


def port_open(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


def wait_healthy(base: str, proc: subprocess.Popen, seconds: int = 15) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"listener exited early with code {proc.returncode}")
        try:
            if SESSION.get(base + "/health", timeout=1).status_code == 200:
                return
        except requests.ConnectionError:
            time.sleep(0.2)
    raise RuntimeError(f"listener not healthy after {seconds}s")


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


def run_gate(host: str, port: int) -> str | None:
    """Return None on pass, or a failure reason."""
    base = f"http://{host}:{port}"
    if port_open(host, port):
        return f"port {port} already in use; not touching it"
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    proc = subprocess.Popen(
        [sys.executable, "-m", "traps.honeypot_server", "--config", "config.yaml", "--db", DB_PATH],
        cwd=ROOT)
    try:
        wait_healthy(base, proc)
        for path, run_id in (("/exfil", "gate1-exfil"), ("/api/v1/webhook", "gate1-webhook")):
            r = SESSION.post(base + path, data=BODY, headers={"X-Run-Id": run_id}, timeout=5)
            out(f"POST {path} run_id={run_id} -> {r.status_code} {r.text}")
        exfil = fetch_events(DB_PATH, "gate1-exfil")
        webhook = fetch_events(DB_PATH, "gate1-webhook")
        for run_id, rows in (("gate1-exfil", exfil), ("gate1-webhook", webhook)):
            if len(rows) != 1:
                return f"expected 1 row for {run_id}, got {len(rows)}"
        show("events row: /exfil", exfil[0])
        show("events row: /api/v1/webhook", webhook[0])
        out("Equivalent commands:")
        for path, run_id in (("/exfil", "gate1-exfil"), ("/api/v1/webhook", "gate1-webhook")):
            out(f'  curl.exe -X POST {base}{path} -H "X-Run-Id: {run_id}" -d "{BODY}"')
        e, w = exfil[0], webhook[0]
        if not (e["tripwire_canary_exfiltrated"] and e["tripwire_honeypot_endpoint_hit"]):
            return "exfil row must have both tripwires true"
        if not w["tripwire_canary_exfiltrated"] or w["tripwire_honeypot_endpoint_hit"]:
            return "webhook row must have exfiltrated true and endpoint_hit false"
        return None
    finally:
        stop(proc)
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
    except (RuntimeError, requests.RequestException, OSError, KeyError) as exc:
        reason = f"{type(exc).__name__}: {exc}"
    out("GATE 1: PASS" if reason is None else f"GATE 1: FAIL {reason}")
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    with open(TXT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return 0 if reason is None else 1


if __name__ == "__main__":
    sys.exit(main())
