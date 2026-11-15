import json

import pytest

import batch_plan


def _plan():
    return batch_plan.build_plan(
        "b1", ["a", "h"], ["s1", "s2", "s3", "s4", "s5", "s6"], [0.1, 0.3, 0.7], 3, False,
        {"a": [0.1, 0.3, 0.7], "h": [None]}, ["run_eval.py", "--models", "a,h"])


def test_build_plan_counts_runs():
    plan = _plan()
    assert plan["planned_runs"] == 72
    assert plan["pid"] is None and plan["started_at"] is None and plan["ended_at"] is None
    assert plan["aborted"] is None and plan["abort_reason"] is None
    assert plan["command"] == ["run_eval.py", "--models", "a,h"]


def test_write_read_finalise_plan_round_trip(tmp_path):
    out = str(tmp_path)
    path = batch_plan.write_plan(out, _plan())
    assert path.endswith(batch_plan.PLAN_FILE)
    assert batch_plan.read_plan(out) == json.loads(json.dumps(_plan()))
    batch_plan.update_plan(out, pid=4242, started_at="t0")
    batch_plan.finalise_plan(out, "t1", True, "stopped")
    plan = batch_plan.read_plan(out)
    assert (plan["pid"], plan["started_at"], plan["ended_at"]) == (4242, "t0", "t1")
    assert plan["aborted"] is True and plan["abort_reason"] == "stopped"
    assert [p.name for p in tmp_path.iterdir()] == [batch_plan.PLAN_FILE]  # no temp file left


def test_read_plan_absent_is_none(tmp_path):
    assert batch_plan.read_plan(str(tmp_path)) is None


@pytest.mark.parametrize("text", ["[1, 2]", "not json", ""])
def test_read_plan_not_object_raises(tmp_path, text):
    (tmp_path / batch_plan.PLAN_FILE).write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="batch.json"):
        batch_plan.read_plan(str(tmp_path))


def test_update_plan_unknown_field_raises(tmp_path):
    batch_plan.write_plan(str(tmp_path), _plan())
    with pytest.raises(KeyError):
        batch_plan.update_plan(str(tmp_path), nonsense=1)
