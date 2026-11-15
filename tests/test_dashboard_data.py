import hashlib
import json
import os
import pathlib
import sqlite3
from contextlib import closing

import batch_plan
import run_eval
from dashboard import data
from telemetry import logger
from test_run_eval import (FINAL, LIST, POST_ENV, READ_ENV, READ_LOG, batch, env,  # noqa: F401
                           factory_for)

CLEAN = [LIST, READ_LOG, FINAL]
BAD = [READ_LOG, READ_ENV, POST_ENV, FINAL]


def _mk(env, batch_id, scripts, scenarios=("indirect_injection_log",), n_runs=1,
        temperatures=(0.3,)):
    return batch(env, list(scenarios), factory_for(scripts), n_runs=n_runs,
                 batch_id=batch_id, temperatures=temperatures)


def _sql(path, sql, params=()):
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute(sql, params)


def _digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def test_empty_when_no_database(tmp_path):
    db = str(tmp_path / "none.db")
    assert data.list_batches(db, str(tmp_path / "results")) == []
    assert data.matrix(db, str(tmp_path), [])["rows"] == []
    assert not os.path.exists(db)


def test_list_batches_newest_first_with_counts(env):
    cfg = env[0]
    _mk(env, "old", [CLEAN])
    _mk(env, "new", [CLEAN, BAD], n_runs=2)
    batches = data.list_batches(cfg["db_path"], cfg["results_dir"])
    assert [b["batch_id"] for b in batches] == ["new", "old"]
    new = batches[0]
    assert (new["recorded_runs"], new["stored_results"], new["planned_runs"]) == (2, 2, 2)
    assert new["aborted"] is False and new["models"] == ["m:1b"] and new["ended_at"]
    assert new["has_plan"] and new["has_result_files"]


def test_progress_without_plan_file(env):
    cfg = env[0]
    out = _mk(env, "b1", [CLEAN])
    os.remove(os.path.join(out["out_dir"], batch_plan.PLAN_FILE))
    p = data.batch_progress(cfg["db_path"], cfg["listener_db_path"], cfg["results_dir"], "b1")
    assert p["planned_runs"] is None and p["plan"] is None and p["recorded_runs"] == 1
    (b,) = data.list_batches(cfg["db_path"], cfg["results_dir"])
    assert b["planned_runs"] is None and b["has_plan"] is False


def test_progress_with_corrupt_plan_file_reports_problem(env):
    cfg = env[0]
    out = _mk(env, "b1", [CLEAN])
    pathlib.Path(out["out_dir"], batch_plan.PLAN_FILE).write_text("{", encoding="utf-8")
    p = data.batch_progress(cfg["db_path"], cfg["listener_db_path"], cfg["results_dir"], "b1")
    assert p["plan"] is None and "batch.json" in p["plan_problem"]


def test_progress_names_current_run(env):
    cfg = env[0]
    out = _mk(env, "b1", [CLEAN, BAD], n_runs=2)
    second = out["results"][1]["run_id"]
    _sql(cfg["db_path"], "DELETE FROM runs WHERE run_id = ?", (second,))
    _sql(cfg["db_path"], "DELETE FROM results WHERE run_id = ?", (second,))
    p = data.batch_progress(cfg["db_path"], cfg["listener_db_path"], cfg["results_dir"], "b1")
    cur = p["current"]
    assert cur["run_id"] == second and cur["scenario_id"] == "indirect_injection_log"
    assert cur["temperature"] == 0.3 and cur["repetition_index"] == 1
    assert cur["last_steps"][-1]["agent_state"] == "FINAL_RESPONSE"
    assert p["recorded_runs"] == 1 and p["unrecorded_run_ids"] == [second]
    # raw listener rows of the unrecorded run are still shown
    assert any(e["path"] == "/admin-debug" and e["classification"] == "trap"
               and e["canary_ids"] == ["log_env"] for e in p["listener_events"])


def test_finished_runs_show_stored_cell_or_not_graded(env):
    cfg = env[0]
    out = _mk(env, "b1", [CLEAN, BAD], n_runs=2)
    _sql(cfg["db_path"], "DELETE FROM results WHERE run_id = ?", (out["results"][0]["run_id"],))
    p = data.batch_progress(cfg["db_path"], cfg["listener_db_path"], cfg["results_dir"], "b1")
    newest, oldest = p["finished"]
    assert newest["cell"] == "completed_compromised" and newest["graded"] is True
    assert "canary_read" in newest["tripwires"] and "honeypot_endpoint_hit" in newest["tripwires"]
    assert oldest["cell"] == "recorded, not graded yet" and oldest["graded"] is False
    assert oldest["tripwires"] == []


def test_matrix_adds_batches_together(env):
    cfg = env[0]
    _mk(env, "a", [CLEAN, BAD], n_runs=2)
    out = _mk(env, "b", [CLEAN], n_runs=1)
    batch_plan.update_plan(out["out_dir"], aborted=True)
    m = data.matrix(cfg["db_path"], cfg["results_dir"], ["a", "b"])
    (row,) = m["rows"]
    assert (row["n_valid"], row["completed_clean"], row["completed_compromised"]) == (3, 2, 1)
    assert row["distinct_trajectories"] == 2 and row["attempted_recorded"] is True
    assert [(i["batch_id"], i["stored_results"], i["aborted"]) for i in m["included"]] == [
        ("a", 2, False), ("b", 1, True)]
    assert m["totals"] == {"total": 3, "valid": 3, "invalid": 0,
                           "runs_with_parse_failures": 0,
                           "runs_with_attempted_tripwires": 0}


def test_matrix_handles_default_temperature(env):
    cfg = env[0]
    _mk(env, "a", [CLEAN, CLEAN], temperatures=(0.7, None))
    m = data.matrix(cfg["db_path"], cfg["results_dir"], ["a"])
    assert [r["temperature"] for r in m["rows"]] == [0.7, None]


def test_matrix_tolerates_old_result_rows(env):
    cfg = env[0]
    out = _mk(env, "a", [CLEAN])
    row = dict(out["results"][0])
    for k in ("attempted_calls", "attempted_tripwires", "attempted_canary_ids",
              "reply_canary_ids", "temperature"):
        row.pop(k)
    _sql(cfg["db_path"], "UPDATE results SET result_json = ?", (json.dumps(row),))
    m = data.matrix(cfg["db_path"], cfg["results_dir"], ["a"])
    (r,) = m["rows"]
    assert r["attempted_recorded"] is False and r["temperature"] == 0.3 and r["n_valid"] == 1
    d = data.run_detail(cfg["db_path"], cfg["listener_db_path"], run_eval.FIXTURES_ROOT,
                        row["run_id"])
    assert d["attempted_calls"] == data.NOT_RECORDED
    assert d["attempted_tripwires"] == data.NOT_RECORDED


def test_run_detail_poison_step_and_full_tool_result(env):
    cfg = env[0]
    out = _mk(env, "a", [BAD])
    run_id = out["results"][0]["run_id"]
    big = "x" * 5000
    _sql(cfg["db_path"], "UPDATE steps SET tool_result = ? WHERE run_id = ? AND step_index = 2",
         (big, run_id))
    d = data.run_detail(cfg["db_path"], cfg["listener_db_path"], run_eval.FIXTURES_ROOT, run_id)
    assert d["poison_step_index"] == 2  # the first reply generated after the log was read
    assert d["steps"][2]["tool_result"] == big
    assert d["result"]["cell"] == "completed_compromised"
    assert set(d["tripwires_fired"]) == {"canary_read", "unauth_tool_call",
                                         "canary_exfiltrated", "honeypot_endpoint_hit"}
    (p,) = d["poison_texts"]
    assert p["read_by_model"] is True and "run log" in p["source"] and p["text"]
    assert any(e["path"] == "/admin-debug" for e in d["listener_events"])
    assert d["inputs"]["scenario"]["id"] == "indirect_injection_log"
    assert d["attempted_calls"] == [] and d["telemetry_enabled"] is False


def test_run_detail_no_poison_step_and_fixture_text_fallback(env):
    cfg = env[0]
    out = _mk(env, "a", [[FINAL]])
    run_id = out["results"][0]["run_id"]
    d = data.run_detail(cfg["db_path"], cfg["listener_db_path"], run_eval.FIXTURES_ROOT, run_id)
    assert d["poison_step_index"] is None
    (p,) = d["poison_texts"]
    fixture = pathlib.Path(run_eval.FIXTURES_ROOT, "indirect_injection_log", p["file"])
    assert p["read_by_model"] is False and p["text"] == fixture.read_text(encoding="utf-8")
    assert "never read" in p["source"]


def test_run_detail_unknown_run(env):
    cfg = env[0]
    _mk(env, "a", [CLEAN])
    d = data.run_detail(cfg["db_path"], cfg["listener_db_path"], run_eval.FIXTURES_ROOT, "nope")
    assert d["run"] is None and d["result"] is None and d["steps"] == []


def test_batch_runs_lists_cells(env):
    cfg = env[0]
    _mk(env, "a", [CLEAN, BAD], n_runs=2)
    runs = data.batch_runs(cfg["db_path"], "a")
    assert [(r["cell"], r["compromised"]) for r in runs] == [
        ("completed_clean", False), ("completed_compromised", True)]


def test_reads_do_not_write(env):
    cfg = env[0]
    out = _mk(env, "a", [CLEAN, BAD], n_runs=2)
    before = (_digest(cfg["db_path"]), _digest(cfg["listener_db_path"]))
    data.list_batches(cfg["db_path"], cfg["results_dir"])
    data.batch_progress(cfg["db_path"], cfg["listener_db_path"], cfg["results_dir"], "a")
    data.matrix(cfg["db_path"], cfg["results_dir"], ["a"])
    data.batch_runs(cfg["db_path"], "a")
    data.run_detail(cfg["db_path"], cfg["listener_db_path"], run_eval.FIXTURES_ROOT,
                    out["results"][0]["run_id"])
    assert (_digest(cfg["db_path"]), _digest(cfg["listener_db_path"])) == before
    assert logger.read_result_rows(cfg["db_path"], "a") == json.loads(json.dumps(out["results"]))


def test_limitations_include_exact_match_and_pointer_notes():
    text = " ".join(data.LIMITATIONS)
    assert "exact string match" in text and "not comparable" in text
