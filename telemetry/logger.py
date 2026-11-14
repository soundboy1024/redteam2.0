"""Run log writer and reader: SQLite plus JSONL. One connection per call.

Every row is validated before anything is written. SQLite is written first,
then the JSONL line; a failure in either raises to the caller.
"""
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone

from telemetry.schema import (AGENT_STATES, BOOL_COLUMNS, DDL, RUN_COLUMNS,
                              RUN_STATUSES, STEP_COLUMNS)


@dataclass
class BatchLog:
    batch_id: str
    db_path: str
    out_dir: str            # results/<batch_id>/, created


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_keys(row: dict, columns: tuple, what: str) -> None:
    if not isinstance(row, dict):
        raise ValueError(f"{what} must be a dict, got {type(row).__name__}")
    missing = [c for c in columns if c not in row]
    unexpected = [k for k in row if k not in columns]
    if missing or unexpected:
        raise KeyError(f"{what} keys wrong: missing {missing}, unexpected {unexpected}")


def _check_common(row: dict) -> None:
    run_id = row["run_id"]
    if not isinstance(run_id, str) or not run_id:
        raise ValueError(f"run_id must be a non-empty string, got {run_id!r}")
    for col in BOOL_COLUMNS:
        if col in row and not isinstance(row[col], bool):
            raise ValueError(f"{col} must be a bool, got {row[col]!r}")


def _check_step(row: dict) -> None:
    _check_keys(row, STEP_COLUMNS, "step row")
    _check_common(row)
    if row["agent_state"] not in AGENT_STATES:
        raise ValueError(f"agent_state {row['agent_state']!r} not in {AGENT_STATES}")


def _check_run(log: BatchLog, run: dict) -> None:
    _check_keys(run, RUN_COLUMNS, "run row")
    _check_common(run)
    if run["status"] not in RUN_STATUSES:
        raise ValueError(f"status {run['status']!r} not in {RUN_STATUSES}")
    if run["batch_id"] != log.batch_id:
        raise ValueError(f"run batch_id {run['batch_id']!r} != batch {log.batch_id!r}")


def _db_values(row: dict, columns: tuple) -> list:
    return [int(row[c]) if c in BOOL_COLUMNS else row[c] for c in columns]


def _insert(db_path: str, table: str, columns: tuple, values: list) -> None:
    sql = (f"INSERT INTO {table} ({', '.join(columns)}) "
           f"VALUES ({', '.join('?' * len(columns))})")
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute(sql, values)


def _append_line(path: str, obj: dict) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(obj, ensure_ascii=False, default=repr) + "\n")


def _bad_batch_id(batch_id) -> bool:
    return (not isinstance(batch_id, str) or not batch_id or ".." in batch_id
            or any(ch in batch_id for ch in "/\\:") or batch_id != batch_id.strip())


def open_batch(db_path: str, results_dir: str, batch_id: str) -> BatchLog:
    if _bad_batch_id(batch_id):
        raise ValueError(f"invalid batch_id {batch_id!r}")
    out_dir = os.path.join(results_dir, batch_id)
    if os.path.exists(os.path.join(out_dir, "steps.jsonl")):
        raise ValueError(f"batch folder {out_dir} already has steps.jsonl; "
                         "use a new batch_id")
    os.makedirs(out_dir, exist_ok=True)
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            for statement in DDL:
                conn.execute(statement)
    return BatchLog(batch_id=batch_id, db_path=db_path, out_dir=out_dir)


def log_step(log: BatchLog, row: dict) -> None:
    _check_step(row)
    line = {c: row[c] for c in STEP_COLUMNS}
    json.dumps(line, ensure_ascii=False, default=repr)  # fail before any write
    _insert(log.db_path, "steps", STEP_COLUMNS, _db_values(row, STEP_COLUMNS))
    _append_line(os.path.join(log.out_dir, "steps.jsonl"), line)


def log_tool_event(log: BatchLog, run_id: str, event: dict) -> None:
    if not isinstance(run_id, str) or not run_id:
        raise ValueError(f"run_id must be a non-empty string, got {run_id!r}")
    if not isinstance(event, dict):
        raise ValueError(f"event must be a dict, got {type(event).__name__}")
    name = event.get("event")
    if not isinstance(name, str) or not name:
        raise ValueError(f"event needs a non-empty string 'event' name, got {name!r}")
    if "run_id" in event and event["run_id"] != run_id:
        raise ValueError(f"event run_id {event['run_id']!r} != run_id {run_id!r}")
    detail = {k: v for k, v in event.items() if k not in ("event", "run_id")}
    if "timestamp" in detail:
        raise ValueError("event detail may not contain 'timestamp'; it is set at write time")
    detail_json = json.dumps(detail, ensure_ascii=False, default=repr)
    timestamp = _now()
    _insert(log.db_path, "tool_events", ("run_id", "timestamp", "event", "detail_json"),
            [run_id, timestamp, name, detail_json])
    _append_line(os.path.join(log.out_dir, "tool_events.jsonl"),
                 {"run_id": run_id, "timestamp": timestamp, "event": name,
                  **json.loads(detail_json)})


def log_run(log: BatchLog, run: dict) -> None:
    _check_run(log, run)
    try:
        _insert(log.db_path, "runs", RUN_COLUMNS, _db_values(run, RUN_COLUMNS))
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"run {run['run_id']!r} already logged: {exc}") from exc


def _fetch(db_path: str, sql: str, params: tuple) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(sql, params).fetchall()


def _decode(row: sqlite3.Row, columns: tuple) -> dict:
    return {c: (bool(row[c]) if c in BOOL_COLUMNS and row[c] is not None else row[c])
            for c in columns}


def read_runs(db_path: str, batch_id: str) -> list[dict]:
    rows = _fetch(db_path, "SELECT * FROM runs WHERE batch_id = ? ORDER BY rowid",
                  (batch_id,))
    return [_decode(r, RUN_COLUMNS) for r in rows]


def read_steps(db_path: str, run_id: str) -> list[dict]:
    rows = _fetch(db_path, "SELECT * FROM steps WHERE run_id = ? ORDER BY step_index, id",
                  (run_id,))
    return [_decode(r, STEP_COLUMNS) for r in rows]


def read_tool_events(db_path: str, run_id: str) -> list[dict]:
    rows = _fetch(db_path, "SELECT * FROM tool_events WHERE run_id = ? ORDER BY id",
                  (run_id,))
    return [{"event": r["event"], "timestamp": r["timestamp"],
             **json.loads(r["detail_json"])} for r in rows]
