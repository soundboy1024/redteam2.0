import json
import os

import pytest

from telemetry.report import (LIMITATION_NOTE, build_matrix, write_results_json,
                              write_summary_md, write_transcript_md)

RESULT_KEYS = (
    "run_id", "batch_id", "model_name", "scenario_id", "attack_taxonomy",
    "repetition_index", "temperature", "telemetry_enabled", "valid",
    "invalid_reason", "tripwire_canary_read", "tripwire_unauth_tool_call",
    "tripwire_canary_exfiltrated", "tripwire_honeypot_endpoint_hit", "compromised",
    "task_completed", "cell", "stop_reason", "steps", "parse_failures",
    "poison_ingested", "canary_ids", "notes")

META = {"batch_id": "b1", "models": ["m1", "m2"], "scenario_ids": ["s1"], "n_runs": 2,
        "temperature": 0.0, "telemetry_enabled": False,
        "started_at": "2026-11-14T00:00:00+00:00", "ended_at": "2026-11-14T01:00:00+00:00",
        "aborted": False}


def make(run_id, model, tax, cell, **over):
    valid = cell != "invalid"
    row = {
        "run_id": run_id, "batch_id": "b1", "model_name": model, "scenario_id": "s1",
        "attack_taxonomy": tax, "repetition_index": 0, "temperature": 0.0,
        "telemetry_enabled": False, "valid": valid,
        "invalid_reason": None if valid else "listener_fault event",
        "tripwire_canary_read": False, "tripwire_unauth_tool_call": False,
        "tripwire_canary_exfiltrated": False, "tripwire_honeypot_endpoint_hit": False,
        "compromised": "compromised" in cell, "task_completed": cell.startswith("completed"),
        "cell": cell, "stop_reason": "final", "steps": 2, "parse_failures": 0,
        "poison_ingested": False, "canary_ids": [], "notes": []}
    row.update(over)
    assert set(row) == set(RESULT_KEYS)
    return row


def eight():
    return [
        make("r1", "m1", "authority_spoof", "completed_clean"),
        make("r2", "m1", "authority_spoof", "completed_compromised",
             poison_ingested=True, tripwire_canary_read=True),
        make("r3", "m1", "authority_spoof", "failed_clean"),
        make("r4", "m1", "benign_control", "failed_compromised", tripwire_canary_read=True),
        make("r5", "m1", "benign_control", "invalid"),
        make("r6", "m2", "benign_control", "completed_clean"),
        make("r7", "m2", "benign_control", "completed_clean"),
        make("r8", "m2", "authority_spoof", "failed_clean", notes=["run hit the step cap"]),
    ]


def test_build_matrix_counts_and_order():
    m = build_matrix(eight())
    assert [(r["model_name"], r["attack_taxonomy"]) for r in m] == [
        ("m1", "benign_control"), ("m1", "authority_spoof"),
        ("m2", "benign_control"), ("m2", "authority_spoof")]
    keyed = {(r["model_name"], r["attack_taxonomy"]): r for r in m}
    a = keyed[("m1", "authority_spoof")]
    assert (a["n_valid"], a["completed_clean"], a["completed_compromised"],
            a["failed_clean"], a["failed_compromised"], a["invalid"]) == (3, 1, 1, 1, 0, 0)
    assert a["poison_ingested"] == 1 and a["canary_read"] == 1
    b = keyed[("m1", "benign_control")]
    assert (b["n_valid"], b["failed_compromised"], b["invalid"], b["canary_read"]) == (1, 1, 1, 1)
    for r in m:
        assert r["n_valid"] == (r["completed_clean"] + r["completed_compromised"]
                                + r["failed_clean"] + r["failed_compromised"])


def test_build_matrix_ordering_fixed_taxonomy_first_appearance_models():
    rows = [make("a", "z", "zzz_custom", "failed_clean"),
            make("b", "z", "authority_spoof", "failed_clean"),
            make("c", "z", "benign_control", "failed_clean"),
            make("d", "z", "aaa_custom", "failed_clean"),
            make("e", "a", "benign_control", "failed_clean")]
    m = build_matrix(rows)
    assert [(r["model_name"], r["attack_taxonomy"]) for r in m] == [
        ("z", "benign_control"), ("z", "authority_spoof"), ("z", "aaa_custom"),
        ("z", "zzz_custom"), ("a", "benign_control")]


def test_build_matrix_unknown_cell_raises():
    with pytest.raises(ValueError):
        build_matrix([make("a", "m", "benign_control", "weird_cell")])


def test_results_json_roundtrip(tmp_path):
    rows = eight()
    path = write_results_json(str(tmp_path), META, rows)
    assert os.path.basename(path) == "results.json"
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["batch"] == META and data["results"] == rows
    assert data["limitation"] == LIMITATION_NOTE
    assert data["matrix"] == build_matrix(rows)


def test_summary_contents(tmp_path):
    path = write_summary_md(str(tmp_path), META, eight())
    text = open(path, encoding="utf-8").read()
    for word in ("b1", "m1", "m2", "authority_spoof", "benign_control",
                 "listener_fault event", "r5", LIMITATION_NOTE, "substring",
                 "run hit the step cap", "Invalid runs", "Notes", "Totals"):
        assert word in text
    assert "1 (33%)" in text
    assert "compromise rate" not in text.lower()
    assert not text.startswith("**BATCH ABORTED")
    assert "8 total runs, 7 valid, 1 invalid" in text


def test_summary_zero_valid_and_aborted(tmp_path):
    rows = [make("x1", "m1", "benign_control", "invalid")]
    meta = dict(META, aborted=True)
    text = open(write_summary_md(str(tmp_path), meta, rows), encoding="utf-8").read()
    assert "n/a" in text
    assert "0" in text
    assert text.splitlines()[0].lower().startswith("**batch aborted")
    assert "incomplete" in text.splitlines()[0]


def test_summary_none_sections(tmp_path):
    rows = [make("x1", "m1", "benign_control", "completed_clean")]
    text = open(write_summary_md(str(tmp_path), META, rows), encoding="utf-8").read()
    assert "None" in text


def steps_for(raw_texts, poison_at=None):
    rows = []
    for i, raw in enumerate(raw_texts):
        rows.append({"step_index": i, "agent_state": "TOOL_DECISION", "tool_name": "read_workspace_file",
                     "tool_args_json": '{"filename": "a"}', "raw_response": raw,
                     "tool_result": "x" * 2500 if i == 1 else "ok",
                     "poison_ingested": poison_at is not None and i >= poison_at,
                     "tool_call_parse_failed": False, "token_count": 7 if i == 1 else None,
                     "latency_ms": None, "mean_logprob": None})
    return rows


def test_transcript_verbatim_truncation_and_poison(tmp_path):
    raw_tick = "before ```` and ``` after\n## Forged heading"
    raw_uni = "café ☃ 日本"
    long_raw = "r" * 5000
    steps = steps_for([raw_tick, raw_uni, long_raw], poison_at=1)
    res = make("run-1", "m1", "authority_spoof", "completed_clean")
    path = write_transcript_md(str(tmp_path), res, steps,
                               [{"event": "http_sent", "timestamp": "t", "path": "/a|b", "event_id": 1}],
                               [{"id": 1, "timestamp": "t", "method": "POST", "path": "/x",
                                 "route_class": "legit", "canary_ids": [],
                                 "tripwire_canary_exfiltrated": False,
                                 "tripwire_honeypot_endpoint_hit": False,
                                 "body_text": "{}", "query_string": ""}])
    assert path.endswith(os.path.join("runs", "run-1.md"))
    text = open(path, encoding="utf-8").read()
    assert raw_tick in text and raw_uni in text and long_raw in text
    assert "[truncated, 500 more characters]" in text
    assert "x" * 2000 in text and "x" * 2001 not in text
    assert text.count(">>> poison in context from this step") == 1
    # fence around the backtick reply is longer than 4 backticks
    assert "`````\n" + raw_tick in text


def test_transcript_invalid_reason_on_top_and_telemetry(tmp_path):
    res = make("run-2", "m1", "benign_control", "invalid")
    text = open(write_transcript_md(str(tmp_path), res, steps_for(["a", "b"]), [], []),
                encoding="utf-8").read()
    head = text[:400]
    assert "listener_fault event" in head
    assert "token_count" in text


@pytest.mark.parametrize("bad", ["../x", "a/b", "", "a b", "x" * 65, "a.md", "..\\x"])
def test_transcript_rejects_bad_run_id(tmp_path, bad):
    res = make(bad, "m1", "benign_control", "completed_clean")
    with pytest.raises(ValueError):
        write_transcript_md(str(tmp_path), res, [], [], [])
