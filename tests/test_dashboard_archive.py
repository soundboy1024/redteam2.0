"""The Archive page: batches that are not in the current run log, read from their files."""
import json
import os

import pytest

from dashboard import archive
from test_dashboard_app import _run, _text, app_env  # noqa: F401
from test_run_eval import FINAL, LIST, READ_LOG, batch, env, factory_for  # noqa: F401

OLD_RESULTS = {
    "batch": {"batch_id": "old1", "models": ["m:1b"], "aborted": False},
    "limitation": "Canary matching is exact string match.",
    "matrix": [{"model_name": "m:1b", "temperature": 0.3,
                "attack_taxonomy": "benign_control", "n_valid": 1, "completed_clean": 1}],
    "results": [{"run_id": "run-a", "model_name": "m:1b", "scenario_id": "benign_control",
                 "cell": "completed_clean", "compromised": False, "task_completed": True}],
}


def old_batch(results_dir, batch_id="old1", doc=None, summary="# Batch old1\n",
              transcript="<b>model text</b> said hello"):
    folder = os.path.join(results_dir, batch_id)
    os.makedirs(os.path.join(folder, "runs"), exist_ok=True)
    with open(os.path.join(folder, "results.json"), "w", encoding="utf-8") as f:
        f.write(doc if isinstance(doc, str) else json.dumps(doc or OLD_RESULTS))
    if summary is not None:
        with open(os.path.join(folder, "summary.md"), "w", encoding="utf-8") as f:
            f.write(summary)
    if transcript is not None:
        with open(os.path.join(folder, "runs", "run-a.md"), "w", encoding="utf-8") as f:
            f.write(transcript)
    return folder


def test_list_archived_skips_current_batches_underscore_folders_and_empty_ones(tmp_path):
    results = str(tmp_path)
    old_batch(results, "old1")
    old_batch(results, "live1")
    old_batch(results, "_sweep")
    os.makedirs(tmp_path / "no-results")
    assert archive.list_archived(results, ["live1"]) == ["old1"]
    assert archive.list_archived(str(tmp_path / "missing"), []) == []


def test_read_archived_returns_what_was_stored(tmp_path):
    old_batch(str(tmp_path))
    doc = archive.read_archived(str(tmp_path), "old1")
    assert doc["problem"] is None and doc["batch"]["batch_id"] == "old1"
    assert doc["results"][0]["cell"] == "completed_clean"
    assert doc["summary"] == "# Batch old1\n" and "exact string match" in doc["limitation"]


@pytest.mark.parametrize("bad", ["{not json", "[1, 2]"])
def test_read_archived_reports_an_unreadable_results_file(tmp_path, bad):
    old_batch(str(tmp_path), doc=bad)
    doc = archive.read_archived(str(tmp_path), "old1")
    assert "results.json could not be read" in doc["problem"] and doc["results"] == []


def test_read_archived_reports_a_missing_summary_and_tolerates_odd_shapes(tmp_path):
    old_batch(str(tmp_path), doc={"batch": "x", "results": [1, {"run_id": "r"}]},
              summary=None)
    doc = archive.read_archived(str(tmp_path), "old1")
    assert doc["batch"] == {} and doc["results"] == [{"run_id": "r"}]
    assert "summary.md could not be read" in doc["problem"]


def test_archive_refuses_ids_that_could_leave_the_results_folder(tmp_path):
    for bad in ("..", "a/b", "a\\b", ""):
        with pytest.raises(ValueError):
            archive.read_archived(str(tmp_path), bad)
        with pytest.raises(ValueError):
            archive.read_transcript(str(tmp_path), "old1", bad)
    assert archive.read_transcript(str(tmp_path), "old1", "missing") is None


def test_archive_page_shows_an_old_batch_and_not_a_current_one(app_env):
    cfg, _, _ = app_env
    batch(app_env, ["indirect_injection_log"], factory_for([[LIST, READ_LOG, FINAL]]),
          batch_id="live1", temperatures=(0.3,))
    old_batch(cfg["results_dir"])
    at = _run("Archive")
    text = _text(at)
    assert "not in the current run log" in text and "nothing is graded again" in text
    assert [b.options for b in at.selectbox if b.label == "Archived batch"] == [["old1"]]
    assert "completed_clean" in text and "# Batch old1" in text
    assert "exact string match" in text
    # the transcript holds model text: shown as plain text in a code block
    assert any("<b>model text</b> said hello" in str(c.value) for c in at.code)


def test_archive_page_empty(app_env):
    assert "No archived batches." in _text(_run("Archive"))


def test_archive_page_flags_an_aborted_batch_and_a_broken_file(app_env):
    cfg, _, _ = app_env
    doc = dict(OLD_RESULTS, batch={"batch_id": "old1", "aborted": True,
                                   "abort_reason": "consecutive invalid runs"})
    old_batch(cfg["results_dir"], doc=doc, summary=None, transcript=None)
    text = _text(_run("Archive"))
    assert "ABORTED early: consecutive invalid runs" in text
    assert "summary.md could not be read" in text
    assert "No transcript file was stored for this run." in text
