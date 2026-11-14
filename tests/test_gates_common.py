import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "gates"))

import _common  # noqa: E402
from _common import Evidence, clear_evidence, finish, out, run_main, show  # noqa: E402

import pytest  # noqa: E402


def _read(tmp_path, name):
    return (tmp_path / name).read_text(encoding="utf-8")


def test_pass_exit_code_and_final_line(tmp_path, capsys):
    ev = Evidence()
    out(ev, "hello")
    assert finish(ev, "gate7", None, evidence_dir=str(tmp_path)) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "GATE 7: PASS"


def test_fail_exit_code_and_final_line(tmp_path, capsys):
    ev = Evidence()
    assert finish(ev, "gate3", "model x not present", evidence_dir=str(tmp_path)) == 1
    assert capsys.readouterr().out.splitlines()[-1] == "GATE 3: FAIL model x not present"


def test_txt_has_every_line_in_order(tmp_path):
    ev = Evidence()
    out(ev, "one")
    out(ev)
    show(ev, "title", {"a": 1, "b": "x"})
    finish(ev, "gate1", None, evidence_dir=str(tmp_path))
    assert _read(tmp_path, "gate1.txt").splitlines() == [
        "one", "", "--- title ---", "  a: 1", "  b: 'x'", "GATE 1: PASS"]


def test_json_shape_and_roundtrip(tmp_path):
    ev = Evidence()
    ev.data["rows"] = [{"k": 1, "ok": True, "n": None}]
    reason = "FAIL: é \"quoted\" reason; two"
    finish(ev, "gate2", reason, evidence_dir=str(tmp_path))
    doc = json.loads(_read(tmp_path, "gate2.json"))
    assert set(doc) == {"gate", "passed", "failure", "data"}
    assert doc["gate"] == "gate2" and doc["passed"] is False
    assert doc["failure"] == reason
    assert doc["data"] == {"rows": [{"k": 1, "ok": True, "n": None}]}


def test_json_passed_true_failure_null(tmp_path):
    finish(Evidence(), "gate1", None, evidence_dir=str(tmp_path))
    doc = json.loads(_read(tmp_path, "gate1.json"))
    assert doc["passed"] is True and doc["failure"] is None


def test_unserialisable_value_falls_back_to_repr(tmp_path):
    ev = Evidence()
    ev.data["obj"] = object()
    ev.data["s"] = {1, 2}
    finish(ev, "gate1", None, evidence_dir=str(tmp_path))
    doc = json.loads(_read(tmp_path, "gate1.json"))
    assert doc["data"]["obj"].startswith("<object object")
    assert doc["data"]["s"] == repr({1, 2})


def test_nan_and_inf_become_repr_strings(tmp_path):
    ev = Evidence()
    ev.data["x"] = float("nan")
    ev.data["nested"] = [{"y": float("inf")}, float("-inf"), 1.5]
    finish(ev, "gate1", None, evidence_dir=str(tmp_path))
    text = _read(tmp_path, "gate1.json")
    doc = json.loads(text, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    assert doc["data"]["x"] == "nan"
    assert doc["data"]["nested"] == [{"y": "inf"}, "-inf", 1.5]



# ---- final fix wave: F1-F3 ----

def _doc(tmp_path, name):
    return json.loads(_read(tmp_path, f"{name}.json"))


def test_non_string_keys_and_nested_non_finite(tmp_path):
    ev = Evidence()
    ev.data["by_int"] = {1: "a", (2, 3): float("nan"), None: [float("-inf")]}
    assert finish(ev, "gate1", None, evidence_dir=str(tmp_path)) == 0
    doc = _doc(tmp_path, "gate1")
    assert doc["data"]["by_int"] == {"1": "a", "(2, 3)": "nan", "None": ["-inf"]}


def test_unserialisable_data_writes_fail_in_both_files(tmp_path, capsys):
    ev = Evidence()
    loop = []
    loop.append(loop)
    ev.data["loop"] = loop
    assert finish(ev, "gate2", None, evidence_dir=str(tmp_path)) == 1
    doc = _doc(tmp_path, "gate2")
    assert doc["passed"] is False and "could not be serialised" in doc["failure"]
    last = _read(tmp_path, "gate2.txt").splitlines()[-1]
    assert last.startswith("GATE 2: FAIL") and "could not be serialised" in last
    assert capsys.readouterr().out.splitlines()[-1] == last


def test_unserialisable_data_keeps_original_failure(tmp_path):
    ev = Evidence()
    loop = {}
    loop["x"] = loop
    ev.data["loop"] = loop
    finish(ev, "gate2", "real problem", evidence_dir=str(tmp_path))
    assert "real problem" in _doc(tmp_path, "gate2")["failure"]


def test_multiline_failure_collapsed_on_last_line_raw_in_json(tmp_path, capsys):
    reason = "first line\nsecond line\r\nthird"
    assert finish(Evidence(), "gate3", reason, evidence_dir=str(tmp_path)) == 1
    last = "GATE 3: FAIL first line second line third"
    assert capsys.readouterr().out.splitlines()[-1] == last
    assert _read(tmp_path, "gate3.txt").splitlines()[-1] == last
    assert _doc(tmp_path, "gate3")["failure"] == reason


def test_finish_writes_via_temp_and_replace(tmp_path, monkeypatch):
    replaced = []
    real = _common.os.replace

    def spy(src, dst):
        replaced.append((os.path.dirname(src), os.path.basename(dst)))
        real(src, dst)
    monkeypatch.setattr(_common.os, "replace", spy)
    finish(Evidence(), "gate1", None, evidence_dir=str(tmp_path))
    assert sorted(b for _, b in replaced) == ["gate1.json", "gate1.txt"]
    assert all(d == str(tmp_path) for d, _ in replaced)
    assert sorted(os.listdir(tmp_path)) == ["gate1.json", "gate1.txt"]


def test_finish_write_failure_leaves_no_new_files(tmp_path, monkeypatch):
    def boom(src, dst):
        raise OSError("disk")
    monkeypatch.setattr(_common.os, "replace", boom)
    with pytest.raises(OSError):
        finish(Evidence(), "gate1", None, evidence_dir=str(tmp_path))
    assert os.listdir(tmp_path) == []


def test_clear_evidence_removes_only_that_gate(tmp_path):
    for name in ("gate1.txt", "gate1.json", "gate2.txt", "gate1.db"):
        (tmp_path / name).write_text("old", encoding="utf-8")
    clear_evidence("gate1", evidence_dir=str(tmp_path))
    assert sorted(os.listdir(tmp_path)) == ["gate1.db", "gate2.txt"]
    clear_evidence("gate9", evidence_dir=str(tmp_path))  # nothing to remove is fine


def test_run_main_records_any_exception_with_traceback(tmp_path, capsys):
    (tmp_path / "gate2.txt").write_text("stale PASS", encoding="utf-8")

    def body(ev):
        out(ev, "started")
        raise LookupError("boom\nsecond")
    assert run_main("gate2", body, evidence_dir=str(tmp_path)) == 1
    doc = _doc(tmp_path, "gate2")
    assert doc["passed"] is False and doc["failure"] == "LookupError: boom\nsecond"
    assert "Traceback" in doc["data"]["traceback"] and "LookupError" in doc["data"]["traceback"]
    lines = _read(tmp_path, "gate2.txt").splitlines()
    assert lines[0] == "started" and lines[-1] == "GATE 2: FAIL LookupError: boom second"
    assert "stale" not in _read(tmp_path, "gate2.txt")


def test_run_main_pass_and_returned_failure(tmp_path):
    assert run_main("gate1", lambda ev: None, evidence_dir=str(tmp_path)) == 0
    assert run_main("gate1", lambda ev: "nope", evidence_dir=str(tmp_path)) == 1
    assert _doc(tmp_path, "gate1")["failure"] == "nope"


def test_run_main_does_not_catch_keyboard_interrupt_and_clears_stale(tmp_path):
    (tmp_path / "gate3.txt").write_text("GATE 3: PASS", encoding="utf-8")
    (tmp_path / "gate3.json").write_text("{}", encoding="utf-8")

    def body(ev):
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        run_main("gate3", body, evidence_dir=str(tmp_path))
    assert os.listdir(tmp_path) == []
