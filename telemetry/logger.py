"""Run log writer and reader: SQLite plus JSONL. One connection per call.

Every row is validated before anything is written. SQLite is written first,
then the JSONL line; a failure in either raises to the caller.
"""
import json
import math
import os
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone

from telemetry.schema import (AGENT_STATES, BOOL_COLUMNS, DDL, INTEGER_COLUMNS,
                              REAL_COLUMNS, RUN_COLUMNS, RUN_STATUSES,
                              SCHEMA_VERSION, STEP_COLUMNS)

INT64_MIN, INT64_MAX = -(2 ** 63), 2 ** 63 - 1
MAX_DETAIL_DEPTH = 50
CIRCULAR = "<circular>"
JSONL_FILES = ("steps.jsonl", "tool_events.jsonl")
BATCH_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL",
                  *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


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


def _clean_text(s: str) -> str:
    """Lone surrogates become visible backslash-u escapes; nothing else changes."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def _normalize(row: dict, columns: tuple) -> dict:
    """Type-check every column and return the values to store (and to write as JSON)."""
    out = {}
    for col in columns:
        v = row[col]
        if col in BOOL_COLUMNS:
            if not isinstance(v, bool):
                raise ValueError(f"{col} must be a bool, got {type(v).__name__} {v!r}")
        elif v is None:
            pass
        elif col in INTEGER_COLUMNS:
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValueError(f"{col} must be an int or None, got {type(v).__name__}")
            if not INT64_MIN <= v <= INT64_MAX:
                raise ValueError(f"{col} is outside the signed 64-bit range: {v}")
        elif col in REAL_COLUMNS:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError(f"{col} must be a number or None, got {type(v).__name__}")
            try:
                v = float(v)
            except OverflowError as exc:
                raise ValueError(f"{col} is too large to store as a float") from exc
            if not math.isfinite(v):
                raise ValueError(f"{col} must be finite, got {v!r}")
        else:
            if not isinstance(v, str):
                raise ValueError(f"{col} must be a str or None, got {type(v).__name__}")
            v = _clean_text(v)
        out[col] = v
    return out


def _check_run_id(row: dict) -> None:
    run_id = row["run_id"]
    if not isinstance(run_id, str) or not run_id:
        raise ValueError(f"run_id must be a non-empty string, got {run_id!r}")


def _check_step(row: dict) -> dict:
    _check_keys(row, STEP_COLUMNS, "step row")
    _check_run_id(row)
    norm = _normalize(row, STEP_COLUMNS)
    if norm["agent_state"] not in AGENT_STATES:
        raise ValueError(f"agent_state {row['agent_state']!r} not in {AGENT_STATES}")
    return norm


def _check_run(log: BatchLog, run: dict) -> dict:
    _check_keys(run, RUN_COLUMNS, "run row")
    _check_run_id(run)
    norm = _normalize(run, RUN_COLUMNS)
    if norm["status"] not in RUN_STATUSES:
        raise ValueError(f"status {run['status']!r} not in {RUN_STATUSES}")
    if norm["batch_id"] != log.batch_id:
        raise ValueError(f"run batch_id {run['batch_id']!r} != batch {log.batch_id!r}")
    return norm


def _db_values(row: dict, columns: tuple) -> list:
    return [int(row[c]) if c in BOOL_COLUMNS else row[c] for c in columns]


def _sanitize_detail(v, _path=()):
    """Recursive: clean strings (keys too), turn non-finite floats into their repr,
    and replace a container that contains itself (or nests too deep) with a marker."""
    if isinstance(v, str):
        return _clean_text(v)
    if isinstance(v, float):
        return v if math.isfinite(v) else repr(v)
    if isinstance(v, (dict, list, tuple)):
        if id(v) in _path or len(_path) >= MAX_DETAIL_DEPTH:
            return CIRCULAR
        path = _path + (id(v),)
        if isinstance(v, dict):
            out = {}
            for k, val in v.items():
                if isinstance(k, str):
                    k = _clean_text(k)
                elif not (k is None or isinstance(k, (bool, int))):
                    k = _clean_text(repr(k))
                out[k] = _sanitize_detail(val, path)
            return out
        return [_sanitize_detail(x, path) for x in v]
    return v


def _dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=lambda o: _clean_text(repr(o)),
                      allow_nan=False)


def _insert(db_path: str, table: str, columns: tuple, values: list) -> None:
    sql = (f"INSERT INTO {table} ({', '.join(columns)}) "
           f"VALUES ({', '.join('?' * len(columns))})")
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            conn.execute(sql, values)


def _append_line(path: str, obj: dict) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(_dumps(obj) + "\n")


def _bad_batch_id(batch_id) -> bool:
    return (not isinstance(batch_id, str) or not BATCH_ID_RE.fullmatch(batch_id)
            or batch_id.upper() in RESERVED_NAMES)


def open_batch(db_path: str, results_dir: str, batch_id: str) -> BatchLog:
    if _bad_batch_id(batch_id):
        raise ValueError(f"invalid batch_id {batch_id!r}")
    out_dir = os.path.join(results_dir, batch_id)
    if os.path.exists(out_dir):
        raise ValueError(f"batch folder {out_dir} already exists; use a new batch_id")
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    _prepare_db(db_path)  # before the folder, so a refused database leaves nothing behind
    os.makedirs(out_dir)
    for name in JSONL_FILES:  # always present, so a missing file means a lost write
        open(os.path.join(out_dir, name), "x", encoding="utf-8").close()
    return BatchLog(batch_id=batch_id, db_path=db_path, out_dir=out_dir)


def _prepare_db(db_path: str) -> None:
    """New database: create the tables and stamp SCHEMA_VERSION. Existing database:
    refuse it unless it carries SCHEMA_VERSION. No migration."""
    with closing(sqlite3.connect(db_path)) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        has_tables = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0] > 0
        if version != SCHEMA_VERSION and (version != 0 or has_tables):
            raise ValueError(
                f"the run log at {db_path} was written by an older schema (user_version "
                f"{version}, expected {SCHEMA_VERSION}) and should be moved aside "
                "before running again")
        with conn:
            for statement in DDL:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")


def log_step(log: BatchLog, row: dict) -> None:
    norm = _check_step(row)
    _dumps(norm)  # fail before any write
    try:
        _insert(log.db_path, "steps", STEP_COLUMNS, _db_values(norm, STEP_COLUMNS))
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"step already logged for run_id {norm['run_id']!r}, "
                         f"step_index {norm['step_index']!r}: {exc}") from exc
    _append_line(os.path.join(log.out_dir, "steps.jsonl"), norm)


def log_tool_event(log: BatchLog, run_id: str, event: dict) -> None:
    if not isinstance(run_id, str) or not run_id:
        raise ValueError(f"run_id must be a non-empty string, got {run_id!r}")
    if not isinstance(event, dict):
        raise ValueError(f"event must be a dict, got {type(event).__name__}")
    run_id = _clean_text(run_id)
    name = event.get("event")
    if not isinstance(name, str) or not name:
        raise ValueError(f"event needs a non-empty string 'event' name, got {name!r}")
    name = _clean_text(name)
    ev_run_id = event.get("run_id")
    if "run_id" in event and (_clean_text(ev_run_id) if isinstance(ev_run_id, str)
                              else ev_run_id) != run_id:
        raise ValueError(f"event run_id {event['run_id']!r} != run_id {run_id!r}")
    detail = _sanitize_detail(
        {k: v for k, v in event.items() if k not in ("event", "run_id")})
    if "timestamp" in detail:
        raise ValueError("event detail may not contain 'timestamp'; it is set at write time")
    detail_json = _dumps(detail)
    timestamp = _now()
    _insert(log.db_path, "tool_events", ("run_id", "timestamp", "event", "detail_json"),
            [run_id, timestamp, name, detail_json])
    _append_line(os.path.join(log.out_dir, "tool_events.jsonl"),
                 {"run_id": run_id, "timestamp": timestamp, "event": name,
                  **json.loads(detail_json)})


def log_run(log: BatchLog, run: dict) -> None:
    norm = _check_run(log, run)
    try:
        _insert(log.db_path, "runs", RUN_COLUMNS, _db_values(norm, RUN_COLUMNS))
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
