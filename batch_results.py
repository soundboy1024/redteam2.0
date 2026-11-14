"""Results half of a batch: grade the logged runs, write the results folder, and store
the graded rows in the run log. Called once per batch by run_eval, on every exit path.
"""
import hashlib

from telemetry.grader import grade_batch
from telemetry.logger import log_result, read_run_inputs, read_steps, read_tool_events
from telemetry.report import (write_results_json, write_summary_md,
                              write_transcript_md)
from traps.events_db import fetch_events


class LogWriteError(RuntimeError):
    """The run log could not be written. Not caught by run_one: the batch aborts."""


def trajectory_hash(steps: list[dict]) -> str:
    """SHA-256 hex of the run's reply texts (step_index >= 1, in order) joined with
    the record separator; a None reply counts as an empty string."""
    replies = [s["raw_response"] or "" for s in sorted(steps, key=lambda s: s["step_index"])
               if s["step_index"] >= 1]
    return hashlib.sha256("\x1e".join(replies).encode("utf-8")).hexdigest()


def write_batch_results(cfg: dict, batch_log, scenarios: list[dict], meta: dict) -> list[dict]:
    """Grade every run recorded for the batch, write the files, then store the grades.
    Files come first so a failing database still leaves the readable results behind."""
    db_path, listener_db = cfg["db_path"], cfg["listener_db_path"]
    results = grade_batch(db_path, listener_db, batch_log.batch_id, scenarios,
                          cfg["canaries"])
    hashes = {r["run_id"]: trajectory_hash(read_steps(db_path, r["run_id"]))
              for r in results}
    write_results_json(batch_log.out_dir, meta, results, trajectory_hashes=hashes)
    write_summary_md(batch_log.out_dir, meta, results, trajectory_hashes=hashes)
    for r in results:
        write_transcript_md(
            batch_log.out_dir, r, read_steps(db_path, r["run_id"]),
            read_tool_events(db_path, r["run_id"]),
            fetch_events(listener_db, r["run_id"]),
            run_inputs=read_run_inputs(db_path, r["run_id"]))
    for r in results:
        try:
            log_result(batch_log, r)
        except Exception as exc:
            raise LogWriteError(f"results table write failed for run {r['run_id']!r}: "
                                f"{type(exc).__name__}: {exc}") from exc
    return results
