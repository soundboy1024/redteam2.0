"""Results half of a batch: grade the logged runs, write the results folder, and store
the graded rows in the run log. Called once per batch by run_eval, on every exit path.
"""
from telemetry.grader import grade_logged_run
from telemetry.logger import (log_result, read_result_rows, read_run_inputs, read_runs,
                              read_steps, read_tool_events)
from telemetry.report import (write_results_json, write_summary_md,
                              write_transcript_md)
from telemetry.trajectory import trajectory_hash  # noqa: F401  (re-exported)
from traps.events_db import fetch_events


class LogWriteError(RuntimeError):
    """The run log could not be written. Not caught by run_one: the batch aborts."""


def _store(batch_log, row: dict) -> None:
    try:
        log_result(batch_log, row)
    except Exception as exc:
        raise LogWriteError(f"results table write failed for run {row['run_id']!r}: "
                            f"{type(exc).__name__}: {exc}") from exc


def grade_and_store_run(cfg: dict, batch_log, scenarios: list[dict], run_id: str) -> dict:
    """Grade one recorded run and store its row. Called as each run finishes, so a
    live view has a grade to show. A run that already has a stored row is an error:
    stored rows are never overwritten."""
    runs = [r for r in read_runs(cfg["db_path"], batch_log.batch_id)
            if r["run_id"] == run_id]
    if len(runs) != 1:
        raise LogWriteError(f"run {run_id!r} is not recorded in batch "
                            f"{batch_log.batch_id!r}")
    row = grade_logged_run(cfg["db_path"], cfg["listener_db_path"], runs[0],
                           {s["id"]: s for s in scenarios}, cfg["canaries"])
    _store(batch_log, row)
    return row


def write_batch_results(cfg: dict, batch_log, scenarios: list[dict], meta: dict,
                        batch_notes: list[str] | None = None) -> list[dict]:
    """Finish a batch: keep every stored result row, grade the runs that have none,
    write the files from the merged list, then store the newly graded rows.
    Files come first so a failing database still leaves the readable results behind."""
    db_path, listener_db = cfg["db_path"], cfg["listener_db_path"]
    stored = {r["run_id"]: r for r in read_result_rows(db_path, batch_log.batch_id)}
    by_id = {s["id"]: s for s in scenarios}
    results, fresh = [], []
    for run in read_runs(db_path, batch_log.batch_id):
        if run["run_id"] in stored:
            results.append(stored[run["run_id"]])
            continue
        row = grade_logged_run(db_path, listener_db, run, by_id, cfg["canaries"])
        results.append(row)
        fresh.append(row)
    hashes = {r["run_id"]: trajectory_hash(read_steps(db_path, r["run_id"]))
              for r in results}
    write_results_json(batch_log.out_dir, meta, results, trajectory_hashes=hashes)
    write_summary_md(batch_log.out_dir, meta, results, trajectory_hashes=hashes,
                     batch_notes=batch_notes)
    for r in results:
        write_transcript_md(
            batch_log.out_dir, r, read_steps(db_path, r["run_id"]),
            read_tool_events(db_path, r["run_id"]),
            fetch_events(listener_db, r["run_id"]),
            run_inputs=read_run_inputs(db_path, r["run_id"]))
    for r in fresh:
        _store(batch_log, r)
    return results
