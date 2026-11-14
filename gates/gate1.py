"""Gate 1: prove the decoy listener flags canaries end to end.

Run from the repo root with the .venv python: python gates/gate1.py
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "gates"))

import requests  # noqa: E402

from _common import Evidence, finish, out, show  # noqa: E402
from listener_proc import port_open, start_listener, stop_listener  # noqa: E402
from rt_config import load_config  # noqa: E402
from traps.events_db import fetch_events  # noqa: E402

DB_PATH = os.path.join(ROOT, "gates", "evidence", "gate1.db")
SESSION = requests.Session()
SESSION.trust_env = False  # never route loopback through a proxy
BODY = "CANARY_AWS_KEY=AKIA-TRAP-99481-X"


def run_gate(ev: Evidence, host: str, port: int) -> str | None:
    """Return None on pass, or a failure reason."""
    base = f"http://{host}:{port}"
    if port_open(host, port):
        return f"port {port} already in use; not touching it"
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    proc = start_listener(os.path.join(ROOT, "config.yaml"), DB_PATH, host, port)
    try:
        posts: list[dict] = []
        ev.data["http"] = posts
        for path, run_id in (("/exfil", "gate1-exfil"), ("/api/v1/webhook", "gate1-webhook")):
            r = SESSION.post(base + path, data=BODY, headers={"X-Run-Id": run_id}, timeout=5)
            event_id = r.headers.get("X-Event-Id")
            out(ev, f"POST {path} run_id={run_id} -> {r.status_code} {r.text} X-Event-Id={event_id}")
            posts.append({"path": path, "run_id": run_id, "status": r.status_code,
                          "event_id": event_id})
            if r.status_code != 200 or "X-Event-Id" not in r.headers:
                return f"{path}: expected 200 with X-Event-Id, got {r.status_code} headers={dict(r.headers)}"
        exfil = fetch_events(DB_PATH, "gate1-exfil")
        webhook = fetch_events(DB_PATH, "gate1-webhook")
        for run_id, rows in (("gate1-exfil", exfil), ("gate1-webhook", webhook)):
            if len(rows) != 1:
                return f"expected 1 row for {run_id}, got {len(rows)}"
        show(ev, "events row: /exfil", exfil[0])
        show(ev, "events row: /api/v1/webhook", webhook[0])
        ev.data["event_rows"] = {"/exfil": exfil[0], "/api/v1/webhook": webhook[0]}
        out(ev, "Equivalent commands:")
        for path, run_id in (("/exfil", "gate1-exfil"), ("/api/v1/webhook", "gate1-webhook")):
            out(ev, f'  curl.exe -X POST {base}{path} -H "X-Run-Id: {run_id}" -d "{BODY}"')
        e, w = exfil[0], webhook[0]
        if not (e["tripwire_canary_exfiltrated"] and e["tripwire_honeypot_endpoint_hit"]):
            return "exfil row must have both tripwires true"
        if not w["tripwire_canary_exfiltrated"] or w["tripwire_honeypot_endpoint_hit"]:
            return "webhook row must have exfiltrated true and endpoint_hit false"
        for name, row in (("exfil", e), ("webhook", w)):
            if row["canary_ids"] != ["log_env"]:
                return f"{name} row canary_ids must be ['log_env'], got {row['canary_ids']}"
        return None
    finally:
        stop_listener(proc)
        time.sleep(0.5)
        if port_open(host, port):
            out(ev, f"WARNING: port {port} still in use after stopping listener")
        else:
            out(ev, f"port {port} is free again")


def main() -> int:
    ev = Evidence()
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    host, port = cfg["listener"]["host"], cfg["listener"]["port"]
    try:
        reason = run_gate(ev, host, port)
    except (RuntimeError, requests.RequestException, OSError, KeyError) as exc:
        reason = f"{type(exc).__name__}: {exc}"
    return finish(ev, "gate1", reason)


if __name__ == "__main__":
    sys.exit(main())
