import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "gates"))

from _common import Evidence, finish, out, show  # noqa: E402


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
