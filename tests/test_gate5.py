import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "gates"))

import _common  # noqa: E402
import gate5  # noqa: E402
import sweep_record as sr  # noqa: E402

TEMPS = [0.1, 0.3, 0.7]


@pytest.fixture
def sweepdir(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "EVIDENCE_DIR", str(tmp_path / "evidence"))
    results = tmp_path / "results"
    monkeypatch.setattr(gate5, "load_config",
                        lambda path: {"results_dir": str(results), "temperatures": TEMPS})
    return results


def _batch(results, bid, rows=18, planned=18, aborted=False):
    d = results / bid
    d.mkdir(parents=True)
    (d / "batch.json").write_text(json.dumps(
        {"batch_id": bid, "planned_runs": planned, "ended_at": "t", "aborted": aborted}))
    (d / "results.json").write_text(json.dumps({"results": [{"valid": True}] * rows}))
    return {"batch_id": bid, "ok": True, "valid": rows, "invalid": 0, "reason": None}


def _build(results, good=None, bad=None, marker=True, skipped_line=True, batches=None):
    sdir = sr.sweep_dir(str(results), "g5")
    ok = sr.new_record("tiny:1b")
    ok.update(status="completed", pulled_by_sweep=True, deleted=True, installed_after=False,
              backend="Vulkan",
              batches=batches if batches is not None else
              [_batch(results, f"sweep-g5-tiny-1b-t0{i}") for i in (1, 3, 7)])
    ok.update(good or {})
    nope = sr.new_record("no-such-model:1b")
    nope.update(status="pull_failed", pulled_by_sweep=False, deleted=False,
                reason="POST /api/pull returned an error: not found")
    nope.update(bad or {})
    sr.write_records(sdir, "g5", [ok, nope])
    if marker:
        sr.mark_done(sdir, "tiny:1b")
    with open(os.path.join(sdir, "sweep.log"), "w", encoding="utf-8") as f:
        f.write("INFO tiny:1b: starting (attempt 1)\n")
        if skipped_line:
            f.write("INFO tiny:1b: done in an earlier run of this sweep, skipped\n")
    return sdir


def _main(tmp_path):
    rc = gate5.main(["--sweep-id", "g5"])
    ev = tmp_path / "evidence"
    return rc, json.loads((ev / "gate5.json").read_text(encoding="utf-8")), \
        (ev / "gate5.txt").read_text(encoding="utf-8")


def test_gate5_passes(sweepdir, tmp_path):
    _build(sweepdir)
    rc, doc, txt = _main(tmp_path)
    assert rc == 0 and doc["passed"] is True and txt.splitlines()[-1] == "GATE 5: PASS"
    assert "tiny:1b" in txt and "completed" in txt and "pull_failed" in txt
    assert "exact string match" in txt and "director's call" in txt
    assert len(doc["data"]["records"]) == 2


@pytest.mark.parametrize("kwargs,needle", [
    ({"good": {"deleted": False}}, "not deleted"),
    ({"good": {"installed_after": True}}, "still installed"),
    ({"good": {"pulled_by_sweep": False}}, "pulled by the sweep"),
    ({"good": {"status": "batch_failed"}}, "no completed model"),
    ({"bad": {"status": "completed", "pulled_by_sweep": True, "deleted": True,
              "installed_after": False}}, "no pull_failed"),
    ({"marker": False}, "done marker"),
    ({"skipped_line": False}, "second start"),
    ({"batches": []}, "3 batches"),
])
def test_gate5_fails(sweepdir, tmp_path, kwargs, needle):
    _build(sweepdir, **kwargs)
    rc, doc, txt = _main(tmp_path)
    assert rc == 1 and needle in doc["failure"], doc["failure"]
    assert txt.splitlines()[-1].startswith("GATE 5: FAIL")


def test_gate5_checks_the_batch_folders_themselves(sweepdir, tmp_path):
    batches = [_batch(sweepdir, "sweep-g5-tiny-1b-t01"),
               _batch(sweepdir, "sweep-g5-tiny-1b-t03", rows=17),
               _batch(sweepdir, "sweep-g5-tiny-1b-t07", aborted=True)]
    _build(sweepdir, batches=batches)
    rc, doc, _ = _main(tmp_path)
    assert rc == 1 and "17 of 18" in doc["failure"] and "aborted" in doc["failure"]


def test_gate5_marker_for_a_failed_model_fails(sweepdir, tmp_path):
    sdir = _build(sweepdir)
    sr.mark_done(sdir, "no-such-model:1b")
    rc, doc, _ = _main(tmp_path)
    assert rc == 1 and "no-such-model:1b" in doc["failure"]


def test_gate5_unknown_sweep_fails(sweepdir, tmp_path):
    rc, doc, _ = _main(tmp_path)
    assert rc == 1 and "no sweep record" in doc["failure"]
