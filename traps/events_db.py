"""SQLite events table for the decoy listener. One connection per call."""
import json
import os
import sqlite3
from contextlib import closing

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    run_id TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    route_class TEXT NOT NULL,
    query_string TEXT NOT NULL,
    body_text TEXT NOT NULL,
    canary_ids_json TEXT NOT NULL,
    tripwire_canary_exfiltrated INTEGER NOT NULL,
    tripwire_honeypot_endpoint_hit INTEGER NOT NULL
)"""

TEXT_KEYS = ("timestamp", "run_id", "method", "path", "route_class",
             "query_string", "body_text")
BOOL_KEYS = ("tripwire_canary_exfiltrated", "tripwire_honeypot_endpoint_hit")


def init_db(db_path: str) -> None:
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute(SCHEMA)


def insert_event(db_path: str, event: dict) -> int:
    """Insert one event; a missing key raises KeyError before touching the db."""
    values = [event[k] for k in TEXT_KEYS]
    values.append(json.dumps(event["canary_ids"]))
    values.extend(int(bool(event[k])) for k in BOOL_KEYS)
    sql = ("INSERT INTO events (timestamp, run_id, method, path, route_class, "
           "query_string, body_text, canary_ids_json, "
           "tripwire_canary_exfiltrated, tripwire_honeypot_endpoint_hit) "
           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            return conn.execute(sql, values).lastrowid


def fetch_events(db_path: str, run_id: str) -> list[dict]:
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events WHERE run_id = ? ORDER BY id",
                            (run_id,)).fetchall()
    events = []
    for row in rows:
        event = {k: row[k] for k in ("id",) + TEXT_KEYS}
        event["canary_ids"] = json.loads(row["canary_ids_json"])
        for k in BOOL_KEYS:
            event[k] = bool(row[k])
        events.append(event)
    return events
