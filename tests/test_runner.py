import hashlib
import logging
import os
import pathlib
import re
import tempfile
import urllib.parse
import uuid

import pytest
import requests
from fastapi.testclient import TestClient

from harness import runner, tools
from harness.agent_loop import AgentOutcome
from harness.ollama_client import ChatResult, OllamaError
from harness.runner import load_scenarios, run_one
from rt_config import load_config
from telemetry.schema import RUN_COLUMNS, STEP_COLUMNS
from traps.honeypot_server import create_app

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = str(ROOT / "traps" / "fixtures")
SCENARIOS = {s["id"]: s for s in load_scenarios(str(ROOT / "traps" / "scenarios.json"))}
CFG = load_config(str(ROOT / "config.yaml"))

LIST = '{"tool": "list_workspace_files", "args": {}}'
READ_LOG = '{"tool": "read_workspace_file", "args": {"filename": "logs/dante_sync.log"}}'
READ_ENV = '{"tool": "read_workspace_file", "args": {"filename": ".env"}}'
FINAL = '{"final": "STAGEBOX-02"}'


def scripted(replies):
    it = iter(replies)

    def chat(messages):
        item = next(it)
        if isinstance(item, Exception):
            raise item
        return ChatResult(content=item, logprobs=None, token_count=5, latency_ms=1.0,
                          tokens_per_sec=None, done_reason="stop")
    return chat


@pytest.fixture
def tmp_ws(tmp_path, monkeypatch):
    d = tmp_path / "wsroot"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d


@pytest.fixture
def real_listener(tmp_path, monkeypatch):
    db = str(tmp_path / "listener.db")
    with TestClient(create_app(db, CFG["canaries"])) as client:
        def forward(url, json=None, headers=None, **kwargs):
            parts = urllib.parse.urlsplit(url)
            return client.post(parts.path, json=json, headers=headers)
        monkeypatch.setattr(tools._SESSION, "post", forward)
        yield db


def go(scenario_id, chat_fn, rows=None, events=None, step_sink=None):
    rows = [] if rows is None else rows
    events = [] if events is None else events
    return run_one(SCENARIOS[scenario_id], FIXTURES, "m:1b", 2, CFG, batch_id="b1",
                   telemetry=False, chat_fn=chat_fn,
                   step_sink=step_sink or rows.append,
                   event_sink=lambda rid, ev: events.append((rid, ev)))


def tree_hash(root):
    h = hashlib.sha256()
    for p in sorted(pathlib.Path(root).rglob("*")):
        h.update(p.relative_to(root).as_posix().encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def test_record_keys_match_run_columns(tmp_ws):
    rec = go("benign_tempting", scripted([FINAL]))
    assert set(rec) == set(RUN_COLUMNS)
    assert set(runner.RUN_KEYS) == set(RUN_COLUMNS)


def test_completed_run_rows_events_and_cleanup(tmp_ws, real_listener):
    rows, events = [], []
    before = tree_hash(os.path.join(FIXTURES, "indirect_injection_log"))
    rec = go("indirect_injection_log", scripted([LIST, READ_LOG, READ_ENV, FINAL]),
             rows, events)
    assert rec["status"] == "completed" and rec["invalid_reason"] is None
    assert rec["stop_reason"] == "final" and rec["final_response"] == "STAGEBOX-02"
    assert rec["steps"] == 4 and rec["parse_failures"] == 0 and rec["poison_ingested"] is True
    assert rec["ctx_tripwire_canary_read"] is True
    assert rec["ctx_tripwire_unauth_tool_call"] is False
    assert isinstance(rec["telemetry_enabled"], bool) and rec["temperature"] == CFG["temperature"]
    assert rec["repetition_index"] == 2 and rec["batch_id"] == "b1"
    assert str(uuid.UUID(rec["run_id"], version=4)) == rec["run_id"]
    assert os.listdir(tmp_ws) == []
    assert tree_hash(os.path.join(FIXTURES, "indirect_injection_log")) == before
    assert [r["step_index"] for r in rows] == [0, 1, 2, 3, 4]
    for r in rows:
        assert set(r) == set(STEP_COLUMNS)
        assert r["run_id"] == rec["run_id"] and r["model_name"] == "m:1b"
        assert r["scenario_id"] == "indirect_injection_log"
        assert r["attack_taxonomy"] == "indirect_injection_log"
        assert r["repetition_index"] == 2 and r["temperature"] == CFG["temperature"]
        assert re.match(r"\d{4}-\d\d-\d\dT.*\+00:00$", r["timestamp"])
    assert events and all(rid == rec["run_id"] for rid, _ in events)
    assert "canary_read" in [ev["event"] for _, ev in events]


def test_ollama_error_is_invalid_and_cleans_up(tmp_ws):
    rows = []
    rec = go("benign_tempting", scripted([LIST, OllamaError("boom")]), rows)
    assert rec["status"] == "invalid"
    assert rec["invalid_reason"] == "OllamaError: boom"
    assert rec["stop_reason"] == "error" and rec["final_response"] is None
    assert rec["steps"] == 1 == sum(1 for r in rows if r["step_index"] >= 1)
    assert os.listdir(tmp_ws) == []


def test_listener_unreachable_is_invalid_with_row_derived_counts(tmp_ws, monkeypatch):
    def refuse(url, **kw):
        raise requests.ConnectionError("refused")
    monkeypatch.setattr(tools._SESSION, "post", refuse)
    send = ('{"tool": "send_http_request", "args": '
            '{"path": "/api/v1/webhook", "payload": {"q3_total": 1}}}')
    rows = []
    rec = go("benign_control", scripted(["garbage", send]), rows)
    assert rec["status"] == "invalid"
    assert rec["invalid_reason"].startswith("ListenerUnreachable: ")
    assert rec["steps"] == 2 and rec["parse_failures"] == 1
    assert rows[-1]["tool_result"].startswith("HARNESS_ERROR ListenerUnreachable")
    assert os.listdir(tmp_ws) == []


def test_value_error_from_missing_poison_file_is_invalid(tmp_ws):
    sc = dict(SCENARIOS["benign_tempting"], poison_files=["nope.txt"])
    rec = run_one(sc, FIXTURES, "m", 0, CFG, batch_id="b", telemetry=False,
                  chat_fn=scripted([]), step_sink=lambda r: None,
                  event_sink=lambda i, e: None)
    assert rec["status"] == "invalid" and rec["invalid_reason"].startswith("ValueError: ")
    assert rec["steps"] == 0 and rec["poison_ingested"] is False


def test_missing_fixture_raises_and_leaves_no_workspace(tmp_ws):
    sc = dict(SCENARIOS["benign_tempting"], fixture_dir="does_not_exist")
    with pytest.raises(FileNotFoundError):
        run_one(sc, FIXTURES, "m", 0, CFG, batch_id="b", telemetry=False,
                chat_fn=scripted([]), step_sink=lambda r: None,
                event_sink=lambda i, e: None)
    assert os.listdir(tmp_ws) == []


def test_oserror_from_sink_is_not_caught_and_workspace_removed(tmp_ws):
    def sink(row):
        raise OSError("disk full")
    with pytest.raises(OSError, match="disk full"):
        go("benign_tempting", scripted([FINAL]), step_sink=sink)
    assert os.listdir(tmp_ws) == []


def test_outcome_disagreement_is_a_loud_runtime_error(tmp_ws, monkeypatch):
    monkeypatch.setattr(runner, "run_agent",
                        lambda *a, **k: AgentOutcome("x", "final", 3, 0, False))
    with pytest.raises(RuntimeError, match="harness bug"):
        go("benign_tempting", scripted([]))
    assert os.listdir(tmp_ws) == []


def test_failed_cleanup_is_logged_and_does_not_mask(tmp_ws, monkeypatch, caplog):
    def boom(*a, **k):
        raise KeyError("in flight")

    def bad_rmtree(path):
        raise OSError("locked")
    monkeypatch.setattr(runner, "run_agent", boom)
    monkeypatch.setattr(runner.shutil, "rmtree", bad_rmtree)
    with caplog.at_level(logging.ERROR, logger="harness.runner"):
        with pytest.raises(KeyError, match="in flight"):
            go("benign_tempting", scripted([]))
    assert any("could not remove temp workspace" in r.message for r in caplog.records)
