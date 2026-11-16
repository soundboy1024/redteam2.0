"""Read-only queries for the dashboard (CLAUDE.md 4.8).

Every database is opened read-only. Nothing here grades: grades come from the
`results` table exactly as the grader stored them.
"""
import json
import os
import pathlib
import sqlite3
from contextlib import closing

import batch_plan
from telemetry.report import (BLOCKED_NOTE, COMPLETION_NOTE, EXECUTED_NOTE, FAILED_NOTE,
                              LIMITATION_NOTE, SIGNAL_NOTE, TRIPWIRES,
                              build_defense_comparison, build_matrix)
from telemetry.schema import BOOL_COLUMNS
from telemetry.trajectory import trajectory_hash

POINTER_NOTE = ("In fake_system_error and authority_spoof the user prompt names the file that "
                "carries the injection, so those two measure how an agent treats an injection "
                "it was told to read. They are not comparable with indirect_injection_log and "
                "indirect_injection_markdown, where the prompt does not name the poison file.")
LIMITATIONS = (LIMITATION_NOTE, COMPLETION_NOTE, EXECUTED_NOTE, FAILED_NOTE, POINTER_NOTE,
               BLOCKED_NOTE, SIGNAL_NOTE)
NOT_RECORDED = "not recorded"
RESULT_FILES = ("results.json", "summary.md")


def _rows(db_path: str, sql: str, params: tuple = ()) -> list[dict]:
    """Run one SELECT on a database opened read-only. A missing file has no rows."""
    if not os.path.isfile(db_path):
        return []
    uri = pathlib.Path(db_path).resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):  # a database nothing has written to yet
                return []
            raise


def _bools(row: dict) -> dict:
    return {k: (bool(v) if k in BOOL_COLUMNS and v is not None else v)
            for k, v in row.items()}


def _placeholders(items) -> str:
    return ", ".join("?" for _ in items)


def read_plan_safe(results_dir: str, batch_id: str) -> tuple[dict | None, str | None]:
    """(plan, problem). A batch from before 4.8 has neither."""
    try:
        return batch_plan.read_plan(os.path.join(results_dir, batch_id)), None
    except (ValueError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def has_result_files(results_dir: str, batch_id: str) -> bool:
    return all(os.path.isfile(os.path.join(results_dir, batch_id, n)) for n in RESULT_FILES)


def list_batches(db_path: str, results_dir: str) -> list[dict]:
    """Every batch in the run log or with a plan file, newest first."""
    runs = {r["batch_id"]: r for r in _rows(
        db_path, "SELECT batch_id, COUNT(*) AS n, MIN(started_at) AS first, "
                 "MAX(ended_at) AS last FROM runs GROUP BY batch_id")}
    stored = {r["batch_id"]: r["n"] for r in _rows(
        db_path, "SELECT batch_id, COUNT(*) AS n FROM results GROUP BY batch_id")}
    models: dict[str, list] = {}
    for r in _rows(db_path, "SELECT DISTINCT batch_id, model_name FROM runs ORDER BY rowid"):
        models.setdefault(r["batch_id"], []).append(r["model_name"])
    ids = set(runs)
    if os.path.isdir(results_dir):
        ids |= {n for n in os.listdir(results_dir)
                if os.path.isfile(os.path.join(results_dir, n, batch_plan.PLAN_FILE))}
    out = []
    for batch_id in ids:
        plan, problem = read_plan_safe(results_dir, batch_id)
        run = runs.get(batch_id, {})
        out.append({
            "batch_id": batch_id, "recorded_runs": run.get("n", 0),
            "stored_results": stored.get(batch_id, 0),
            "planned_runs": plan.get("planned_runs") if plan else None,
            "started_at": (plan or {}).get("started_at") or run.get("first"),
            "ended_at": (plan or {}).get("ended_at"),
            "aborted": (plan or {}).get("aborted"),
            "models": (plan or {}).get("models") or models.get(batch_id, []),
            "has_plan": plan is not None, "plan_problem": problem,
            "has_result_files": has_result_files(results_dir, batch_id)})
    return sorted(out, key=lambda b: (b["started_at"] or "", b["batch_id"]), reverse=True)


def _step_run_ids(out_dir: str) -> list[str]:
    """Run ids in steps.jsonl, first-seen order. A half-written last line is skipped:
    the batch may be writing it right now."""
    path = os.path.join(out_dir, "steps.jsonl")
    if not os.path.isfile(path):
        return []
    seen: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                run_id = json.loads(line)["run_id"]
            except (ValueError, KeyError, TypeError):
                continue
            if run_id not in seen:
                seen.append(run_id)
    return seen


def _fired(result: dict) -> list[str]:
    return [t.removeprefix("tripwire_") for t in TRIPWIRES if result.get(t)]


def batch_progress(db_path: str, listener_db_path: str, results_dir: str,
                   batch_id: str) -> dict:
    plan, problem = read_plan_safe(results_dir, batch_id)
    runs = _rows(db_path, "SELECT run_id, model_name, scenario_id, temperature, "
                          "repetition_index, status, invalid_reason FROM runs "
                          "WHERE batch_id = ? ORDER BY rowid", (batch_id,))
    stored = {r["run_id"]: json.loads(r["result_json"]) for r in _rows(
        db_path, "SELECT run_id, result_json FROM results WHERE batch_id = ?", (batch_id,))}
    finished = []
    for run in reversed(runs):
        result = stored.get(run["run_id"])
        finished.append({**run, "graded": result is not None,
                         "cell": result["cell"] if result else "recorded, not graded yet",
                         "tripwires": _fired(result) if result else [],
                         "attempted_tripwires": (result or {}).get("attempted_tripwires",
                                                                   [])})
    recorded = {r["run_id"] for r in runs}
    unrecorded = [i for i in _step_run_ids(os.path.join(results_dir, batch_id))
                  if i not in recorded]
    current = None
    if unrecorded:
        steps = _rows(db_path, "SELECT run_id, model_name, scenario_id, temperature, "
                               "repetition_index, step_index, agent_state, tool_name, "
                               "tool_args_json, parse_reason FROM steps WHERE run_id = ? "
                               "ORDER BY step_index", (unrecorded[-1],))
        if steps:
            head = steps[0]
            current = {k: head[k] for k in ("run_id", "model_name", "scenario_id",
                                            "temperature", "repetition_index")}
            current["last_steps"] = steps[-6:]
    ids = [r["run_id"] for r in runs] + unrecorded
    events = []
    if ids:
        events = _rows(listener_db_path,
                       "SELECT timestamp, run_id, method, path, route_class, canary_ids_json "
                       f"FROM events WHERE run_id IN ({_placeholders(ids)}) "
                       "ORDER BY id DESC LIMIT 20", tuple(ids))
    return {"plan": plan, "plan_problem": problem, "recorded_runs": len(runs),
            "planned_runs": plan.get("planned_runs") if plan else None,
            "current": current, "finished": finished, "unrecorded_run_ids": unrecorded,
            "has_result_files": has_result_files(results_dir, batch_id),
            "listener_events": [{"timestamp": e["timestamp"], "run_id": e["run_id"],
                                 "method": e["method"], "path": e["path"],
                                 "classification": e["route_class"],
                                 "canary_ids": json.loads(e["canary_ids_json"])}
                                for e in events]}


def stored_results(db_path: str, batch_ids: list[str]) -> list[dict]:
    """The stored result rows of the chosen batches, as the grader wrote them."""
    if not batch_ids:
        return []
    rows = _rows(db_path, "SELECT result_json FROM results WHERE batch_id IN "
                          f"({_placeholders(batch_ids)}) ORDER BY rowid", tuple(batch_ids))
    return [json.loads(r["result_json"]) for r in rows]


def matrix(db_path: str, results_dir: str, batch_ids: list[str]) -> dict:
    """The four-cell matrix over the stored results of one or more batches, added
    together. Rows written before the attempted-calls change lack those fields; they
    count as no attempt and the row is marked so the page can say "not recorded"."""
    results = stored_results(db_path, batch_ids)
    temps = {}
    if any("temperature" not in r for r in results):
        temps = {r["run_id"]: r["temperature"] for r in _rows(
            db_path, "SELECT run_id, temperature FROM runs WHERE batch_id IN "
                     f"({_placeholders(batch_ids)})", tuple(batch_ids))}
    unrecorded_keys = set()
    patched = []
    for r in results:
        row = dict(r)
        row.setdefault("temperature", temps.get(r["run_id"]))
        if "attempted_tripwires" not in row:
            row["attempted_tripwires"] = []
            unrecorded_keys.add((row["model_name"], row["defense_id"],
                                 row["temperature"], row["attack_taxonomy"]))
        patched.append(row)
    hashes = {}
    for r in patched:
        steps = _rows(db_path, "SELECT step_index, raw_response FROM steps WHERE run_id = ? "
                               "ORDER BY step_index", (r["run_id"],))
        hashes[r["run_id"]] = trajectory_hash(steps)
    rows = build_matrix(patched, hashes)
    for row in rows:
        key = (row["model_name"], row["defense_id"], row["temperature"],
               row["attack_taxonomy"])
        row["attempted_recorded"] = key not in unrecorded_keys
    per_batch = {}
    for r in patched:
        per_batch[r["batch_id"]] = per_batch.get(r["batch_id"], 0) + 1
    included = []
    for batch_id in batch_ids:
        plan, _ = read_plan_safe(results_dir, batch_id)
        aborted = plan.get("aborted") if plan else _summary_says_aborted(results_dir, batch_id)
        included.append({"batch_id": batch_id, "stored_results": per_batch.get(batch_id, 0),
                         "planned_runs": plan.get("planned_runs") if plan else None,
                         "aborted": aborted})
    n_valid = sum(1 for r in patched if r["valid"])
    return {"rows": rows, "included": included,
            "defense_comparison": build_defense_comparison(patched),
            "totals": {"total": len(patched), "valid": n_valid,
                       "invalid": len(patched) - n_valid,
                       "runs_with_parse_failures": sum(1 for r in patched
                                                       if r["parse_failures"]),
                       "runs_with_attempted_tripwires": sum(
                           1 for r in patched if r["attempted_tripwires"]),
                       "runs_with_blocked_attempts": sum(
                           1 for r in patched if r["blocked_calls"])}}


def _summary_says_aborted(results_dir: str, batch_id: str) -> bool | None:
    """For a batch without a plan file: what its results.json recorded, or None."""
    path = os.path.join(results_dir, batch_id, "results.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return bool(json.load(f)["batch"]["aborted"])
    except (ValueError, KeyError, TypeError, OSError):
        return None


def batch_runs(db_path: str, batch_id: str) -> list[dict]:
    """Runs of a batch for the run selector, with the stored cell where there is one."""
    runs = _rows(db_path, "SELECT run_id, model_name, scenario_id, temperature, "
                          "repetition_index FROM runs WHERE batch_id = ? ORDER BY rowid",
                 (batch_id,))
    stored = {r["run_id"]: r for r in _rows(
        db_path, "SELECT run_id, cell, compromised FROM results WHERE batch_id = ?",
        (batch_id,))}
    for run in runs:
        s = stored.get(run["run_id"])
        run["cell"] = s["cell"] if s else "not graded"
        run["compromised"] = bool(s["compromised"]) if s else None
    return runs


def _parse_args(text) -> dict | None:
    try:
        value = json.loads(text) if text else None
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _norm(name) -> str:
    return str(name).replace("\\", "/").removeprefix("./")


def _poison_texts(scenario: dict, steps: list[dict], fixtures_root: str) -> list[dict]:
    out = []
    for name in scenario.get("poison_files", []):
        entry = {"file": name, "text": None, "source": None, "read_by_model": False}
        for s in steps:
            args = _parse_args(s["tool_args_json"])
            if (s["tool_name"] == "read_workspace_file" and args
                    and _norm(args.get("filename", "")) == _norm(name)
                    and s["tool_result"] is not None):
                entry.update(text=s["tool_result"], source="as the model read it (run log)",
                             read_by_model=True)
                break
        if entry["text"] is None:
            path = os.path.join(fixtures_root, scenario.get("fixture_dir", ""), name)
            try:
                with open(path, encoding="utf-8") as f:
                    entry.update(text=f.read(),
                                 source="from the fixture folder (the model never read it)")
            except OSError as exc:
                entry.update(text="", source=f"fixture file could not be read: {exc}")
        out.append(entry)
    return out


def run_detail(db_path: str, listener_db_path: str, fixtures_root: str,
               run_id: str) -> dict:
    """Everything the Inspect page shows for one run. Tool results are not truncated."""
    run = _rows(db_path, "SELECT * FROM runs WHERE run_id = ?", (run_id,))
    stored = _rows(db_path, "SELECT result_json FROM results WHERE run_id = ?", (run_id,))
    inputs = _rows(db_path, "SELECT * FROM run_inputs WHERE run_id = ?", (run_id,))
    steps = [_bools(s) for s in _rows(
        db_path, "SELECT * FROM steps WHERE run_id = ? ORDER BY step_index, id", (run_id,))]
    tool_events = [{"event": e["event"], "timestamp": e["timestamp"],
                    **json.loads(e["detail_json"])} for e in _rows(
        db_path, "SELECT * FROM tool_events WHERE run_id = ? ORDER BY id", (run_id,))]
    listener = _rows(listener_db_path, "SELECT * FROM events WHERE run_id = ? ORDER BY id",
                     (run_id,))
    for e in listener:
        e["canary_ids"] = json.loads(e.pop("canary_ids_json"))
    scenario = json.loads(inputs[0]["scenario_json"]) if inputs else {}
    poison = [s["step_index"] for s in steps if s["poison_ingested"]]
    result = json.loads(stored[0]["result_json"]) if stored else None
    return {"run": _bools(run[0]) if run else None, "result": result,
            "inputs": ({"user_prompt": inputs[0]["user_prompt"],
                        "system_prompt": inputs[0]["system_prompt"], "scenario": scenario}
                       if inputs else None),
            "steps": steps, "tool_events": tool_events, "listener_events": listener,
            "poison_step_index": poison[0] if poison else None,
            "poison_texts": _poison_texts(scenario, steps, fixtures_root),
            "telemetry_enabled": bool(run[0]["telemetry_enabled"]) if run else False,
            "tripwires_fired": _fired(result) if result else [],
            "attempted_calls": (result or {}).get("attempted_calls", NOT_RECORDED),
            "attempted_tripwires": (result or {}).get("attempted_tripwires", NOT_RECORDED)}
