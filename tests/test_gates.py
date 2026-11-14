"""Gate scripts: failure recording (F1), Gate 3 criteria and output (F4-F6).
No real model, no listener: everything that would touch either is replaced."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "gates"))

import _common  # noqa: E402
import gate1  # noqa: E402
import gate2  # noqa: E402
import gate3  # noqa: E402
from rt_config import ConfigError  # noqa: E402


@pytest.fixture
def evdir(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "EVIDENCE_DIR", str(tmp_path))
    return tmp_path


def _doc(evdir, name):
    return json.loads((evdir / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("mod,name", [(gate1, "gate1"), (gate2, "gate2"), (gate3, "gate3")])
def test_config_failure_is_a_recorded_fail_and_stale_evidence_is_gone(evdir, monkeypatch,
                                                                     capsys, mod, name):
    (evdir / f"{name}.txt").write_text("stale PASS", encoding="utf-8")
    (evdir / f"{name}.json").write_text('{"passed": true}', encoding="utf-8")

    def bad(path):
        raise ConfigError("cannot read config file")
    monkeypatch.setattr(mod, "load_config", bad)
    rc = mod.main([]) if mod is gate3 else mod.main()
    assert rc == 1
    doc = _doc(evdir, name)
    assert doc["passed"] is False
    assert doc["failure"] == "ConfigError: cannot read config file"
    assert "Traceback" in doc["data"]["traceback"]
    txt = (evdir / f"{name}.txt").read_text(encoding="utf-8")
    assert "stale" not in txt
    number = name.removeprefix("gate")
    assert txt.splitlines()[-1] == f"GATE {number}: FAIL ConfigError: cannot read config file"
    assert capsys.readouterr().out.splitlines()[-1] == txt.splitlines()[-1]


def test_gate1_prints_kill_notice(evdir, monkeypatch):
    monkeypatch.setattr(gate1, "port_open", lambda h, p: False)
    monkeypatch.setattr(gate1, "start_listener", lambda *a: "proc")
    monkeypatch.setattr(gate1, "stop_listener", lambda proc: True)
    monkeypatch.setattr(gate1.time, "sleep", lambda s: None)

    def boom(*a, **k):
        raise OSError("refused")
    monkeypatch.setattr(gate1.SESSION, "post", boom)
    monkeypatch.setattr(gate1, "DB_PATH", str(evdir / "gate1.db"))
    assert gate1.main() == 1
    assert "listener ignored terminate; killed" in (evdir / "gate1.txt").read_text(
        encoding="utf-8")


def test_gate2_prints_kill_notice(evdir, monkeypatch):
    monkeypatch.setattr(gate2, "port_open", lambda h, p: False)
    monkeypatch.setattr(gate2, "start_listener", lambda *a: "proc")
    monkeypatch.setattr(gate2, "stop_listener", lambda proc: True)
    monkeypatch.setattr(gate2.time, "sleep", lambda s: None)
    monkeypatch.setattr(gate2, "DB_PATH", str(evdir / "gate2.db"))

    def boom(*a, **k):
        raise RuntimeError("tool step failed")
    monkeypatch.setattr(gate2, "run_tool_steps", boom)
    assert gate2.main() == 1
    assert "listener ignored terminate; killed" in (evdir / "gate2.txt").read_text(
        encoding="utf-8")


# ---- Gate 3 helpers ----

def step(i, run_id, **over):
    s = {"run_id": run_id, "step_index": i, "agent_state": "PRE_POISON", "tool_name": None,
         "tool_call_parse_failed": False, "parse_reason": None, "done_reason": "stop",
         "token_count": 5, "raw_response": "{}", "mean_logprob": None,
         "tool_name_logprob": None, "mean_entropy_approx": None, "entropy_spike_delta": None}
    s.update(over)
    return s


def result(run_id, scenario_id, telemetry, **over):
    r = {"run_id": run_id, "scenario_id": scenario_id, "telemetry_enabled": telemetry,
         "valid": True, "invalid_reason": None, "cell": "completed_clean",
         "task_completed": True, "stop_reason": "final", "steps": 1, "parse_failures": 0,
         "poison_ingested": False, **{t: False for t in gate3.TRIPWIRES}}
    r.update(over)
    return r


def make_folder(path, results):
    os.makedirs(path / "runs", exist_ok=True)
    (path / "results.json").write_text(json.dumps({"results": results}), encoding="utf-8")
    (path / "summary.md").write_text("# s", encoding="utf-8")
    (path / "steps.jsonl").write_text("{}\n", encoding="utf-8")
    (path / "tool_events.jsonl").write_text("", encoding="utf-8")
    for r in results:
        (path / "runs" / f"{r['run_id']}.md").write_text("# t", encoding="utf-8")


def good(tmp_path):
    ra = [result("a1", "benign_control", False), result("a2", "indirect_injection_log", False)]
    rb = [result("b1", "indirect_injection_log", True)]
    make_folder(tmp_path / "A", ra)
    make_folder(tmp_path / "B", rb)
    a = {"out_dir": str(tmp_path / "A"), "results": ra, "aborted": False}
    b = {"out_dir": str(tmp_path / "B"), "results": rb, "aborted": False}
    steps = {"a1": [step(0, "a1"), step(1, "a1")], "a2": [step(0, "a2"), step(1, "a2")],
             "b1": [step(0, "b1"), step(1, "b1", mean_logprob=-0.2)]}
    stored = {"A": [{"run_id": r["run_id"], "cell": r["cell"]} for r in ra],
              "B": [{"run_id": "b1", "cell": "completed_clean"}]}
    return a, b, steps, stored


def failed(criteria):
    return [c["criterion"] for c in criteria if not c["passed"]]


def test_criteria_all_pass(tmp_path):
    crit = gate3.build_criteria(*good(tmp_path))
    assert failed(crit) == [] and len(crit) == 12


def test_criteria_report_every_failure_together(tmp_path):
    a, b, steps, stored = good(tmp_path)
    a["results"][1]["scenario_id"] = "benign_tempting"
    b["results"][0]["telemetry_enabled"] = False
    b["results"][0]["valid"] = False
    a["results"][0]["task_completed"] = None
    steps["a1"] = [step(0, "a1")]
    steps["a2"][1]["mean_logprob"] = -1.0
    steps["b1"][1]["mean_logprob"] = None
    stored["B"] = [{"run_id": "b1", "cell": "failed_clean"}]
    b["aborted"] = True
    names = failed(gate3.build_criteria(a, b, steps, stored))
    assert names == [
        "batch A returned benign_control and indirect_injection_log with telemetry off",
        "batch B returned indirect_injection_log with telemetry on",
        "all three results valid",
        "four tripwires and task_completed are booleans",
        "every returned run has a logged reply step",
        "batch B has a reply step with non-null mean_logprob",
        "batch A has reply steps and none has non-null mean_logprob",
        "results table has one row per returned run with the returned cell",
        "batch B not aborted"]


def test_criteria_extra_result_and_missing_stored_row(tmp_path):
    a, b, steps, stored = good(tmp_path)
    b["results"].append(result("b2", "indirect_injection_log", True))
    stored["A"] = stored["A"][:1]
    names = failed(gate3.build_criteria(a, b, steps, stored))
    assert "batch B returned indirect_injection_log with telemetry on" in names
    assert "results table has one row per returned run with the returned cell" in names
    assert "batch B folder complete" in names  # results.json ids and transcript differ


@pytest.mark.parametrize("breakage", ["empty_summary", "no_tool_events", "bad_ids",
                                      "bad_json", "empty_transcript"])
def test_folder_checks(tmp_path, breakage):
    a, b, steps, stored = good(tmp_path)
    d = tmp_path / "A"
    if breakage == "empty_summary":
        (d / "summary.md").write_text("", encoding="utf-8")
    elif breakage == "no_tool_events":
        os.remove(d / "tool_events.jsonl")
    elif breakage == "bad_ids":
        (d / "results.json").write_text(json.dumps({"results": [{"run_id": "zz"}]}),
                                        encoding="utf-8")
    elif breakage == "bad_json":
        (d / "results.json").write_text("{not json", encoding="utf-8")
    else:
        (d / "runs" / "a2.md").write_text("", encoding="utf-8")
    assert failed(gate3.build_criteria(a, b, steps, stored)) == ["batch A folder complete"]


def test_step_lines_every_reply_step_and_raw_for_parse_failures():
    raw = "line one\nline two " + "x" * 300
    steps = [step(0, "r"), step(1, "r", tool_name="list_workspace_files"),
             step(2, "r", agent_state="PARSE_FAILURE", tool_call_parse_failed=True,
                  parse_reason="invalid JSON: Expecting value", done_reason="length",
                  raw_response=raw)]
    lines = gate3.step_lines(steps, gate3.STEP_KEYS)
    assert len(lines) == 3
    assert lines[0].startswith("  step_index=1, agent_state='PRE_POISON'")
    assert "parse_reason='invalid JSON: Expecting value'" in lines[1]
    assert "done_reason='length'" in lines[1]
    assert lines[2] == "    raw reply (first 200 chars): " + raw[:200].replace("\n", " ")
    b_lines = gate3.step_lines(steps, gate3.B_STEP_KEYS)
    assert "tool_name_logprob=None" in b_lines[0] and "mean_entropy_approx=" in b_lines[0]


def test_parse_reason_counts_and_what_happened():
    steps = [step(1, "r", tool_call_parse_failed=True, parse_reason="no JSON object found"),
             step(2, "r", tool_call_parse_failed=True, parse_reason="duplicate key"),
             step(3, "r", tool_call_parse_failed=True, parse_reason="no JSON object found")]
    assert gate3.parse_reason_counts(steps) == "no JSON object found x2, duplicate key x1"
    assert gate3.parse_reason_counts([step(1, "r")]) == "none"
    lines = gate3.what_happened(result("r", "indirect_injection_log", True,
                                       tripwire_canary_read=True), steps)
    assert "parse failure reasons: no JSON object found x2, duplicate key x1." in lines
    assert "tripwires fired: canary_read." in lines


def test_batch_a_recorded_before_batch_b_fails_and_port_probed(evdir, monkeypatch, tmp_path):
    a = {"out_dir": str(tmp_path / "A"), "results": [result("a1", "benign_control", False)],
         "aborted": False, "abort_reason": None}
    calls = []

    def fake_run_batch(cfg, models, scenarios, n, tele, batch_id, **kw):
        calls.append(batch_id)
        if len(calls) == 2:
            raise RuntimeError("batch B exploded")
        return a
    probes = []
    monkeypatch.setattr(gate3.run_eval, "run_batch", fake_run_batch)
    monkeypatch.setattr(gate3, "precheck", lambda host, model: None)
    monkeypatch.setattr(gate3, "port_open", lambda h, p: probes.append(p) or False)
    monkeypatch.setattr(gate3.time, "sleep", lambda s: None)
    assert gate3.main([]) == 1
    doc = _doc(evdir, "gate3")
    assert doc["failure"] == "RuntimeError: batch B exploded"
    assert doc["data"]["batches"]["A"]["results"][0]["run_id"] == "a1"
    assert doc["data"]["port_free_at_end"] is True and probes
