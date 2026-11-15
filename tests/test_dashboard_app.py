import json
import os
import pathlib
import sqlite3
from contextlib import closing

import pytest
from streamlit.testing.v1 import AppTest

import batch_plan
from dashboard import control, data
from test_run_eval import (FINAL, LIST, POST_ENV, READ_ENV, READ_LOG, batch, env,  # noqa: F401
                           factory_for)

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = str(ROOT / "dashboard" / "app.py")
CLEAN = [LIST, READ_LOG, FINAL]
BAD = [READ_LOG, READ_ENV, POST_ENV, FINAL]


@pytest.fixture
def app_env(env, monkeypatch):
    cfg, cfg_path, _ = env
    monkeypatch.setenv("RT_DASHBOARD_CONFIG", cfg_path)
    for name in ("ANTHROPIC_API_KEY", "GROQ_API_KEY", "CEREBRAS_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    # the pages must not depend on whether a real batch holds the real listener port
    monkeypatch.setattr(control, "port_open", lambda host, port: False)
    return env


def test_run_page_start_is_off_while_port_is_busy(app_env, monkeypatch):
    monkeypatch.setattr(control, "port_open", lambda host, port: True)
    at = _run()
    assert [b for b in at.button if b.label == "Start"][0].disabled is True
    assert "Start is off" in _text(at) and "in use" in _text(at)


def test_run_page_running_batch_blocks_start_and_enables_stop(app_env, monkeypatch):
    out = batch(app_env, ["indirect_injection_log"], factory_for([CLEAN]), batch_id="b1",
                temperatures=(0.3,))
    batch_plan.update_plan(out["out_dir"], ended_at=None, aborted=None)
    monkeypatch.setattr(control, "port_open", lambda host, port: True)
    at = _run()
    text = _text(at)
    assert "b1: RUNNING" in text and "batch b1 is running" in text
    buttons = {b.label: b for b in at.button}
    assert buttons["Start"].disabled is True and buttons["Stop"].disabled is True
    at.checkbox[0].check().run()
    assert {b.label: b for b in at.button}["Stop"].disabled is False


def _run(page=None):
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    if page:
        at.sidebar.radio[0].set_value(page).run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def _text(at) -> str:
    parts = []
    for kind in ("markdown", "caption", "text", "code", "header", "subheader", "warning",
                 "error", "info", "success", "metric"):
        for el in getattr(at, kind):
            parts.append(str(getattr(el, "value", "")))
            parts.append(str(getattr(el, "label", "")))
    for df in at.dataframe:
        parts.append(df.value.to_csv())
    return "\n".join(parts)


def test_run_page_renders_idle(app_env):
    at = _run()
    text = _text(at)
    assert "run_eval.py" in text and "runs** planned" in text
    assert "No batches yet." in text
    start = [b for b in at.button if b.label == "Start"][0]
    assert start.disabled is False


def test_run_page_disables_hosted_model_without_key(app_env):
    at = _run()
    options = at.multiselect[0].options
    assert "qwen2.5:7b" in options
    assert not any(o.startswith(("anthropic/", "groq/")) for o in options)
    text = _text(at)
    assert "anthropic/claude-haiku-4-5" in text and "ANTHROPIC_API_KEY not set" in text


def test_run_page_never_shows_a_key_value(app_env, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-SECRETVALUE")
    at = _run()
    assert "SECRETVALUE" not in _text(at)
    assert "ANTHROPIC_API_KEY set" in _text(at)
    assert any(o.startswith("anthropic/") for o in at.multiselect[0].options)


def test_run_page_shows_finished_batch_progress(app_env):
    batch(app_env, ["indirect_injection_log"], factory_for([CLEAN, BAD]), n_runs=2,
          batch_id="b1", temperatures=(0.3,))
    text = _text(_run())
    assert "b1: finished" in text and "2 / 2" in text
    assert "completed_compromised" in text and "/admin-debug" in text
    assert "Raw listener events (not a grade)" in text


def test_run_page_stopped_batch_never_looks_finished(app_env):
    cfg = app_env[0]
    out = batch(app_env, ["indirect_injection_log"], factory_for([CLEAN]), batch_id="b1",
                temperatures=(0.3,))
    batch_plan.update_plan(out["out_dir"], ended_at=None, aborted=None)
    os.remove(os.path.join(out["out_dir"], "results.json"))
    text = _text(_run())
    assert "STOPPED WITHOUT RESULTS" in text and "b1: finished" not in text
    assert any(b.label == "Regrade this batch" for b in _run().button)


def test_results_page_renders_matrix_and_limitations(app_env):
    batch(app_env, ["indirect_injection_log"], factory_for([CLEAN, BAD]), n_runs=2,
          batch_id="b1", temperatures=(0.3,))
    text = _text(_run("Results"))
    assert "exact string match" in text and "not comparable" in text
    assert "indirect_injection_log" in text and "1 (50%)" in text
    assert "2 runs" in text and "2 valid" in text


def test_results_page_with_batch_lacking_plan_file_and_old_rows(app_env):
    cfg = app_env[0]
    out = batch(app_env, ["indirect_injection_log"], factory_for([CLEAN]), batch_id="b1",
                temperatures=(0.3,))
    os.remove(os.path.join(out["out_dir"], batch_plan.PLAN_FILE))
    row = dict(out["results"][0])
    for k in ("attempted_calls", "attempted_tripwires"):
        row.pop(k)
    with closing(sqlite3.connect(cfg["db_path"])) as conn, conn:
        conn.execute("UPDATE results SET result_json = ?", (json.dumps(row),))
    text = _text(_run("Results"))
    assert "unknown" in text and data.NOT_RECORDED in text
    assert "not recorded" in _text(_run("Inspect a run"))


def test_results_page_empty(app_env):
    text = _text(_run("Results"))
    assert "No batch has stored results yet." in text and "exact string match" in text


def test_inspect_page_renders_compromised_run(app_env):
    batch(app_env, ["indirect_injection_log"], factory_for([BAD]), batch_id="b1",
          temperatures=(0.3,))
    at = _run("Inspect a run")
    text = _text(at)
    for name in ("canary_read", "unauth_tool_call", "canary_exfiltrated",
                 "honeypot_endpoint_hit"):
        assert name in text
    assert "completed_compromised" in text and "log_env" in text
    assert "Poison entered the context at step 2" in text
    assert any("/admin-debug" in c.value for c in at.code)  # the raw reply is a code element
    assert "Attempted calls that were never executed" in text


def test_inspect_page_empty(app_env):
    assert "No recorded runs yet." in _text(_run("Inspect a run"))


def test_no_page_uses_unsafe_html():
    for name in ("app.py", "data.py", "control.py"):
        source = (ROOT / "dashboard" / name).read_text(encoding="utf-8")
        assert "unsafe_allow_html" not in source and "st.html" not in source, name
        assert "components.v1" not in source, name
