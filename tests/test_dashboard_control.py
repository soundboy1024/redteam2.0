import json
import pathlib
import subprocess
import textwrap
import types

import pytest

from dashboard import control
from harness import remote_client
from scripts import check_rules


def test_build_command_exact_argv():
    cmd = control.build_command("py.exe", ["a:1b", "groq/x/y"], ["s1", "s2"], [0.1, 0.3, 1.0],
                                3, "b1", "cfg.yaml")
    assert cmd == ["py.exe", "run_eval.py", "--config", "cfg.yaml", "--models", "a:1b,groq/x/y",
                   "--scenarios", "s1,s2", "--temperatures", "0.1,0.3,1", "--n-runs", "3",
                   "--batch-id", "b1"]


def _fake_run(returncode=0, stdout="", stderr=""):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    return run, calls


def test_preview_plan_ok(monkeypatch):
    run, calls = _fake_run(stdout='INFO noise\n{"planned_runs": 54}\n')
    monkeypatch.setattr(control.subprocess, "run", run)
    plan, problem = control.preview_plan(["py", "run_eval.py"], "C:/x")
    assert plan == {"planned_runs": 54} and problem is None
    assert calls[0][0] == ["py", "run_eval.py", "--plan"] and calls[0][1]["cwd"] == "C:/x"


def test_preview_plan_error_returns_run_eval_message(monkeypatch):
    run, _ = _fake_run(1, stderr="INFO x\nerror: environment variable GROQ_API_KEY is empty\n")
    monkeypatch.setattr(control.subprocess, "run", run)
    plan, problem = control.preview_plan(["py", "run_eval.py"], ".")
    assert plan is None and problem == "error: environment variable GROQ_API_KEY is empty"


def test_preview_plan_garbage_and_timeout(monkeypatch):
    run, _ = _fake_run(0, stdout="not json")
    monkeypatch.setattr(control.subprocess, "run", run)
    assert control.preview_plan(["py"], ".")[0] is None

    def boom(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 30)
    monkeypatch.setattr(control.subprocess, "run", boom)
    plan, problem = control.preview_plan(["py"], ".")
    assert plan is None and "TimeoutExpired" in problem


def test_key_status_never_returns_values():
    secret = "sk-secret-value"
    status = control.key_status(["qwen2.5:7b", "anthropic/claude-x", "groq/a/b", "cerebras/c"],
                                {"ANTHROPIC_API_KEY": secret, "GROQ_API_KEY": ""})
    assert status == {"anthropic/claude-x": True, "groq/a/b": False, "cerebras/c": False}
    assert secret not in json.dumps(status)


def test_key_names_match_harness():
    assert control.KEY_ENV == {p: v["key_env"] for p, v in remote_client.PROVIDERS.items()}
    for model in ("anthropic/x", "groq/a/b", "llama3.2:3b", "hf.co/org/model", "openai/x"):
        assert control.provider_of(model) == remote_client.split_model(model)[0]


@pytest.mark.parametrize("plan,port,files,expected", [
    (None, False, True, "finished"),
    (None, False, False, "unknown"),
    ({"pid": 5, "ended_at": None}, True, False, "running"),
    ({"pid": 5, "ended_at": None}, False, False, "stopped_without_results"),
    ({"pid": None, "ended_at": None}, True, False, "stopped_without_results"),
    ({"pid": 5, "ended_at": "t", "aborted": False}, False, True, "finished"),
    ({"pid": 5, "ended_at": "t", "aborted": True}, False, True, "aborted"),
    ({"pid": 5, "ended_at": "t", "aborted": False}, False, False, "stopped_without_results"),
])
def test_batch_state_table(plan, port, files, expected):
    assert control.batch_state(plan, port, files) == expected
    assert expected in control.STATES


def _no_popen(monkeypatch):
    def popen(*a, **k):
        raise AssertionError("a process was started")
    monkeypatch.setattr(control.subprocess, "Popen", popen)


def test_start_refused_when_port_busy(monkeypatch, tmp_path):
    _no_popen(monkeypatch)
    with pytest.raises(control.StartRefused, match="port"):
        control.start_batch(["py"], ".", str(tmp_path / "c" / "b.log"), True, None)
    assert not (tmp_path / "c").exists()


def test_start_refused_when_batch_running(monkeypatch, tmp_path):
    _no_popen(monkeypatch)
    with pytest.raises(control.StartRefused, match="night-1"):
        control.start_batch(["py"], ".", str(tmp_path / "b.log"), False, "night-1")


def test_start_launches_command_with_console_log(monkeypatch, tmp_path):
    seen = {}

    def popen(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return types.SimpleNamespace(pid=77)
    monkeypatch.setattr(control.subprocess, "Popen", popen)
    log_path = tmp_path / "_console" / "b1.log"
    proc = control.start_batch(["py", "run_eval.py"], "C:/x", str(log_path), False, None)
    assert proc.pid == 77 and seen["argv"] == ["py", "run_eval.py"] and seen["cwd"] == "C:/x"
    assert seen["stderr"] == subprocess.STDOUT and log_path.exists()


@pytest.mark.parametrize("plan", [{"batch_id": "b", "pid": None, "ended_at": None},
                                  {"batch_id": "b", "pid": "12", "ended_at": None},
                                  {"batch_id": "b", "pid": 12, "ended_at": "t"}])
def test_stop_refuses_plan_without_live_pid(monkeypatch, plan):
    run, calls = _fake_run()
    monkeypatch.setattr(control.subprocess, "run", run)
    with pytest.raises(ValueError):
        control.stop_batch(plan, ".", "py", "127.0.0.1", 1)
    assert calls == []


def test_stop_kills_only_plan_pid_then_regrades(monkeypatch):
    run, calls = _fake_run(0, stdout="ok")
    monkeypatch.setattr(control.subprocess, "run", run)
    monkeypatch.setattr(control, "port_open", lambda host, port: False)
    out = control.stop_batch({"batch_id": "b9", "pid": 4321, "ended_at": None}, "C:/x",
                             "py.exe", "127.0.0.1", 8999, "cfg.yaml")
    assert [c[0] for c in calls] == [
        ["taskkill", "/PID", "4321", "/T", "/F"],
        ["py.exe", "run_eval.py", "--config", "cfg.yaml", "--regrade", "b9"]]
    assert out["killed"] is True and out["port_closed"] is True and out["regrade_exit"] == 0


def test_rules_flag_dashboard_importing_harness(tmp_path):
    (tmp_path / "dashboard").mkdir()
    (tmp_path / "harness").mkdir()
    (tmp_path / "dashboard" / "bad.py").write_text(textwrap.dedent("""
        import harness.tools
        from harness import runner
        from telemetry import logger
    """), encoding="utf-8")
    found = check_rules.find_violations(tmp_path)
    assert len(found) == 2 and all("dashboard must not import harness" in v for v in found)


def test_real_dashboard_does_not_import_harness():
    root = pathlib.Path(__file__).resolve().parent.parent
    assert [v for v in check_rules.find_violations(root) if "dashboard" in v] == []
