import json
import os
import sqlite3
from contextlib import closing

import pytest

from telemetry import logger
from telemetry.schema import (AGENT_STATES, IDENTITY_COLUMNS, RUN_COLUMNS,
                              STEP_COLUMNS)

STEP_KEYS = ("step_index", "agent_state", "tool_name", "tool_args_json",
             "tool_call_parse_failed", "raw_response", "tool_result",
             "poison_ingested", "token_count", "latency_ms", "tokens_per_sec",
             "mean_logprob", "min_logprob", "std_logprob", "mean_entropy_approx",
             "max_entropy_approx", "entropy_spike_delta", "tool_name_logprob")


def make_step(run_id="r1", **over):
    row = {"run_id": run_id, "timestamp": "2026-11-14T00:00:00+00:00",
           "model_name": "m", "scenario_id": "s", "attack_taxonomy": "benign_control",
           "repetition_index": 0, "temperature": 0.0,
           "step_index": 0, "agent_state": "PRE_POISON", "tool_name": "list_workspace_files",
           "tool_args_json": "{}", "tool_call_parse_failed": False,
           "raw_response": "café {\"tool\": \"x\"}", "tool_result": None,
           "poison_ingested": False, "token_count": None, "latency_ms": 12.5,
           "tokens_per_sec": None, "mean_logprob": -0.5, "min_logprob": None,
           "std_logprob": None, "mean_entropy_approx": None,
           "max_entropy_approx": None, "entropy_spike_delta": None,
           "tool_name_logprob": None}
    row.update(over)
    return row


def make_run(run_id="r1", batch_id="b1", **over):
    run = {"run_id": run_id, "batch_id": batch_id, "model_name": "m",
           "scenario_id": "s", "attack_taxonomy": "benign_control",
           "repetition_index": 1, "temperature": 0.2, "telemetry_enabled": False,
           "started_at": "t0", "ended_at": "t1", "status": "completed",
           "invalid_reason": None, "stop_reason": "final", "final_response": "ok",
           "steps": 3, "parse_failures": 0, "poison_ingested": True,
           "ctx_tripwire_canary_read": False, "ctx_tripwire_unauth_tool_call": True}
    run.update(over)
    return run


@pytest.fixture
def log(tmp_path):
    return logger.open_batch(str(tmp_path / "runs.db"), str(tmp_path / "results"), "b1")


def jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def count(db, table):
    with closing(sqlite3.connect(db)) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_columns():
    assert STEP_COLUMNS == IDENTITY_COLUMNS + STEP_KEYS
    assert len(RUN_COLUMNS) == 19
    assert "PARSE_FAILURE" in AGENT_STATES


def test_open_batch_creates_dir_and_tables(log):
    assert os.path.isdir(log.out_dir)
    assert os.path.basename(log.out_dir) == "b1"
    assert count(log.db_path, "steps") == 0


@pytest.mark.parametrize("bad", ["", "a/b", "a\\b", "..", "x..y", "C:x", "../up", "a b",
                                 "a.b", "x" * 65, "con", "NUL", "Com1", "lpt9", None, 5, "abc\n", "con\n"])
def test_open_batch_rejects_bad_ids(tmp_path, bad):
    with pytest.raises(ValueError):
        logger.open_batch(str(tmp_path / "r.db"), str(tmp_path / "res"), bad)


def test_open_batch_refuses_existing_folder(log, tmp_path):
    with pytest.raises(ValueError, match="already exists"):
        logger.open_batch(log.db_path, str(tmp_path / "results"), "b1")


def test_open_batch_keeps_rows(log, tmp_path):
    logger.log_step(log, make_step())
    logger.log_run(log, make_run())
    log2 = logger.open_batch(log.db_path, str(tmp_path / "results"), "b2")
    assert len(logger.read_steps(log.db_path, "r1")) == 1
    assert len(logger.read_runs(log.db_path, "b1")) == 1
    assert log2.batch_id == "b2"


def test_step_round_trip_and_jsonl(log):
    row = make_step(tool_call_parse_failed=True, poison_ingested=True, token_count=7)
    logger.log_step(log, row)
    got = logger.read_steps(log.db_path, "r1")
    assert got == [row]
    assert got[0]["tool_call_parse_failed"] is True
    assert got[0]["poison_ingested"] is True
    assert got[0]["tool_result"] is None
    lines = jsonl(os.path.join(log.out_dir, "steps.jsonl"))
    assert lines == [row]
    with open(os.path.join(log.out_dir, "steps.jsonl"), encoding="utf-8") as f:
        assert "café" in f.read()


def test_steps_ordered_by_step_index(log):
    for i in (2, 0, 1):
        logger.log_step(log, make_step(step_index=i, raw_response=str(i)))
    got = logger.read_steps(log.db_path, "r1")
    assert [(r["step_index"], r["raw_response"]) for r in got] == [(0, "0"), (1, "1"), (2, "2")]


def test_duplicate_step_is_loud_and_not_appended(log):
    logger.log_step(log, make_step())
    with pytest.raises(ValueError, match="r1.*step_index 0"):
        logger.log_step(log, make_step(raw_response="again"))
    assert count(log.db_path, "steps") == 1
    assert len(jsonl(os.path.join(log.out_dir, "steps.jsonl"))) == 1


def assert_nothing_written(log):
    assert count(log.db_path, "steps") == 0
    assert not os.path.exists(os.path.join(log.out_dir, "steps.jsonl")) or \
        os.path.getsize(os.path.join(log.out_dir, "steps.jsonl")) == 0


def test_step_missing_key(log):
    row = make_step()
    del row["latency_ms"]
    with pytest.raises(KeyError, match="latency_ms"):
        logger.log_step(log, row)
    assert_nothing_written(log)


def test_step_extra_key(log):
    with pytest.raises(KeyError, match="bonus"):
        logger.log_step(log, make_step(bonus=1))
    assert_nothing_written(log)


@pytest.mark.parametrize("over", [
    {"agent_state": "NOPE"},
    {"tool_call_parse_failed": 1},
    {"poison_ingested": "yes"},
    {"run_id": ""},
    {"run_id": 5},
])
def test_step_bad_values(log, over):
    with pytest.raises(ValueError):
        logger.log_step(log, make_step(**over))
    assert_nothing_written(log)


def test_step_jsonl_failure_raises_after_sqlite(log):
    os.makedirs(os.path.join(log.out_dir, "steps.jsonl"))
    with pytest.raises(OSError):
        logger.log_step(log, make_step())
    assert count(log.db_path, "steps") == 1


def test_tool_event_round_trip(log):
    ev = {"event": "http_sent", "path": "/exfil", "payload": {"k": "café"}, "event_id": 4}
    logger.log_tool_event(log, "r1", dict(ev, run_id="r1"))
    logger.log_tool_event(log, "r1", {"event": "file_read", "filename": "a"})
    got = logger.read_tool_events(log.db_path, "r1")
    assert [g["event"] for g in got] == ["http_sent", "file_read"]
    assert got[0]["payload"] == {"k": "café"} and got[0]["event_id"] == 4
    assert got[0]["timestamp"].endswith("+00:00")
    assert "run_id" not in got[0]
    lines = jsonl(os.path.join(log.out_dir, "tool_events.jsonl"))
    assert lines[0] == {"run_id": "r1", "timestamp": got[0]["timestamp"], **ev}
    assert logger.read_tool_events(log.db_path, "other") == []


def test_tool_event_odd_payload_never_crashes(log):
    logger.log_tool_event(log, "r1", {"event": "x", "obj": {1, 2}})
    got = logger.read_tool_events(log.db_path, "r1")[0]
    assert got["obj"] in ("{1, 2}", "{2, 1}")
    with open(os.path.join(log.out_dir, "tool_events.jsonl"), encoding="utf-8") as f:
        assert json.loads(f.readline())["obj"] == got["obj"]


def test_tool_event_bad(log):
    for run_id, ev in (("r1", {"event": "x", "run_id": "r2"}), ("", {"event": "x"}),
                       ("r1", {"path": "/"}), ("r1", {"event": ""}),
                       ("r1", {"event": "x", "timestamp": "t"})):
        with pytest.raises(ValueError):
            logger.log_tool_event(log, run_id, ev)
    assert count(log.db_path, "tool_events") == 0


def test_tool_event_jsonl_failure_raises(log):
    os.makedirs(os.path.join(log.out_dir, "tool_events.jsonl"))
    with pytest.raises(OSError):
        logger.log_tool_event(log, "r1", {"event": "x"})


def test_run_round_trip(log):
    run = make_run()
    logger.log_run(log, run)
    got = logger.read_runs(log.db_path, "b1")
    assert got == [run]
    assert got[0]["telemetry_enabled"] is False
    assert got[0]["poison_ingested"] is True
    assert got[0]["invalid_reason"] is None


def test_run_validation(log):
    bad = [make_run(status="weird"), make_run(telemetry_enabled=0),
           make_run(ctx_tripwire_canary_read=None), make_run(run_id=""),
           make_run(batch_id="other")]
    for run in bad:
        with pytest.raises(ValueError):
            logger.log_run(log, run)
    short = make_run()
    del short["steps"]
    with pytest.raises(KeyError, match="steps"):
        logger.log_run(log, short)
    assert count(log.db_path, "runs") == 0


def test_duplicate_run_is_loud(log):
    logger.log_run(log, make_run())
    with pytest.raises(ValueError):
        logger.log_run(log, make_run())
    assert count(log.db_path, "runs") == 1


def test_batches_separate_and_ordered(log, tmp_path):
    log2 = logger.open_batch(log.db_path, str(tmp_path / "results"), "b2")
    logger.log_run(log, make_run("r2"))
    logger.log_run(log2, make_run("r9", batch_id="b2"))
    logger.log_run(log, make_run("r1"))
    assert [r["run_id"] for r in logger.read_runs(log.db_path, "b1")] == ["r2", "r1"]
    assert [r["run_id"] for r in logger.read_runs(log.db_path, "b2")] == ["r9"]


# ---- fix round 1: types, non-finite numbers, unencodable text ----

@pytest.mark.parametrize("val", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_real_rejected(log, val):
    with pytest.raises(ValueError, match="mean_logprob"):
        logger.log_step(log, make_step(mean_logprob=val))
    with pytest.raises(ValueError, match="temperature"):
        logger.log_run(log, make_run(temperature=val))
    assert_nothing_written(log)
    assert count(log.db_path, "runs") == 0


@pytest.mark.parametrize("over, col", [
    ({"step_index": 1.0}, "step_index"), ({"step_index": "1"}, "step_index"),
    ({"step_index": True}, "step_index"), ({"token_count": True}, "token_count"),
    ({"latency_ms": "abc"}, "latency_ms"), ({"latency_ms": True}, "latency_ms"),
    ({"tool_name": 5}, "tool_name"), ({"tool_result": b"ab"}, "tool_result"),
    ({"repetition_index": 1.5}, "repetition_index"), ({"temperature": "0.1"}, "temperature"),
    ({"model_name": 3}, "model_name"), ({"poison_ingested": None}, "poison_ingested"),
])
def test_step_wrong_types(log, over, col):
    with pytest.raises(ValueError, match=col):
        logger.log_step(log, make_step(**over))
    assert_nothing_written(log)


@pytest.mark.parametrize("over, col", [
    ({"steps": 3.0}, "steps"), ({"parse_failures": True}, "parse_failures"),
    ({"final_response": 7}, "final_response"), ({"started_at": b"x"}, "started_at"),
])
def test_run_wrong_types(log, over, col):
    with pytest.raises(ValueError, match=col):
        logger.log_run(log, make_run(**over))
    assert count(log.db_path, "runs") == 0


def test_real_given_as_int_is_float_in_both_stores(log):
    logger.log_step(log, make_step(latency_ms=3, temperature=1))
    got = logger.read_steps(log.db_path, "r1")[0]
    line = jsonl(os.path.join(log.out_dir, "steps.jsonl"))[0]
    for src in (got, line):
        assert src["latency_ms"] == 3.0 and isinstance(src["latency_ms"], float)
        assert isinstance(src["temperature"], float)
    with open(os.path.join(log.out_dir, "steps.jsonl"), encoding="utf-8") as f:
        assert '"latency_ms": 3.0' in f.read()


def test_lone_surrogate_in_step_text(log):
    logger.log_step(log, make_step(raw_response="a\ud800b", tool_name="t\udfffx"))
    got = logger.read_steps(log.db_path, "r1")[0]
    assert got["raw_response"] == "a\\ud800b"
    assert got["tool_name"] == "t\\udfffx"
    with open(os.path.join(log.out_dir, "steps.jsonl"), encoding="utf-8") as f:
        line = json.loads(f.readline())
    assert line == got


def test_lone_surrogate_in_run_text(log):
    logger.log_run(log, make_run(final_response="x\ud800"))
    assert logger.read_runs(log.db_path, "b1")[0]["final_response"] == "x\\ud800"


def test_lone_surrogate_in_tool_event(log):
    logger.log_tool_event(log, "r1", {"event": "path_rejected", "filename": "a\ud800",
                                      "nested": {"k\ud800": ["v\udc00", 1]}})
    got = logger.read_tool_events(log.db_path, "r1")[0]
    assert got["filename"] == "a\\ud800"
    assert got["nested"] == {"k\\ud800": ["v\\udc00", 1]}
    with open(os.path.join(log.out_dir, "tool_events.jsonl"), encoding="utf-8") as f:
        line = json.loads(f.readline())
    assert line["filename"] == got["filename"] and line["nested"] == got["nested"]


@pytest.mark.parametrize("val", [2 ** 70, -(2 ** 63) - 1, 2 ** 63])
def test_int_outside_int64_rejected(log, val):
    with pytest.raises(ValueError, match="token_count"):
        logger.log_step(log, make_step(token_count=val))
    with pytest.raises(ValueError, match="steps"):
        logger.log_run(log, make_run(steps=val))
    assert_nothing_written(log)
    logger.log_step(log, make_step(token_count=2 ** 63 - 1))
    assert logger.read_steps(log.db_path, "r1")[0]["token_count"] == 2 ** 63 - 1


def test_circular_tool_event_detail_logs_with_marker(log):
    loop = {"a": 1}
    loop["self"] = loop
    seq = [1]
    seq.append(seq)
    shared = {"s": 1}
    logger.log_tool_event(log, "r1", {"event": "x", "loop": loop, "seq": seq,
                                      "twice": [shared, shared]})
    got = logger.read_tool_events(log.db_path, "r1")[0]
    assert got["loop"] == {"a": 1, "self": "<circular>"}
    assert got["seq"] == [1, "<circular>"]
    assert got["twice"] == [{"s": 1}, {"s": 1}]
    line = jsonl(os.path.join(log.out_dir, "tool_events.jsonl"))[0]
    assert (line["loop"], line["seq"], line["twice"]) == (got["loop"], got["seq"], got["twice"])


def test_too_deep_tool_event_detail_logs(log):
    deep = cur = {}
    for _ in range(5000):
        cur["n"] = {}
        cur = cur["n"]
    logger.log_tool_event(log, "r1", {"event": "x", "deep": deep})
    assert len(logger.read_tool_events(log.db_path, "r1")) == 1


def test_nul_and_newline_round_trip(log):
    text = "a\x00b\nc\r\nd"
    logger.log_step(log, make_step(raw_response=text))
    logger.log_tool_event(log, "r1", {"event": "x", "v": text})
    assert logger.read_steps(log.db_path, "r1")[0]["raw_response"] == text
    assert logger.read_tool_events(log.db_path, "r1")[0]["v"] == text
    assert jsonl(os.path.join(log.out_dir, "steps.jsonl"))[0]["raw_response"] == text


def test_tool_event_non_finite_floats_become_strings(log):
    logger.log_tool_event(log, "r1", {"event": "x", "a": float("nan"),
                                      "b": [float("inf"), {"c": float("-inf")}], "d": 1.5})
    got = logger.read_tool_events(log.db_path, "r1")[0]
    assert (got["a"], got["b"], got["d"]) == ("nan", ["inf", {"c": "-inf"}], 1.5)
    path = os.path.join(log.out_dir, "tool_events.jsonl")
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    assert "NaN" not in raw and "Infinity" not in raw
    line = json.loads(raw)
    assert line["a"] == "nan" and line["b"] == ["inf", {"c": "-inf"}]
