"""Gate 5: the model sweep pulled, ran, confirmed and deleted one real model, recorded a
tag that does not exist as failed, and skipped the finished model on a second start
(director gate).

Run from the repo root with the .venv python, after the Gate 5 sweep has been started twice:
    .venv\\Scripts\\python.exe gates\\gate5.py --sweep-id SWEEP_ID [--config config.yaml]

Starts nothing and calls nothing. It reads the sweep's own record, its log, its done
markers and the batch folders it names.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "gates"))

import sweep_record  # noqa: E402
from _common import Evidence, out, run_main, show  # noqa: E402
from rt_config import load_config  # noqa: E402

VERBATIM = ("Gate 5 checks that the sweep did its steps and kept its record. How a model "
            "behaved in its batches is not part of this gate; judging that is the "
            "director's call.")
SKIPPED = "done in an earlier run of this sweep, skipped"


def _abs(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(ROOT, path)


def check_batch_folder(results_dir: str, bid: str) -> list[str]:
    """Every reason this batch folder does not hold a complete batch."""
    out_dir = os.path.join(results_dir, bid)
    problems = []
    try:
        with open(os.path.join(out_dir, "batch.json"), encoding="utf-8") as f:
            plan = json.load(f)
        with open(os.path.join(out_dir, "results.json"), encoding="utf-8") as f:
            rows = json.load(f)["results"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [f"batch {bid}: files could not be read ({type(exc).__name__}: {exc})"]
    if plan.get("aborted") is not False or not plan.get("ended_at"):
        problems.append(f"batch {bid} is aborted or never ended")
    if len(rows) != plan.get("planned_runs"):
        problems.append(f"batch {bid}: {len(rows)} of {plan.get('planned_runs')} planned "
                        "runs recorded")
    return problems


def check_sweep(records: list[dict], sdir: str, results_dir: str, n_temperatures: int,
                log_text: str) -> list[str]:
    """Every reason this sweep does not satisfy Gate 5. Empty means it does."""
    failed = []
    completed = [r for r in records if r["status"] == "completed"]
    pull_failed = [r for r in records if r["status"] == "pull_failed"]
    if not completed:
        failed.append("no completed model in the record")
    if not pull_failed:
        failed.append("no pull_failed model in the record")
    for r in completed:
        tag = r["tag"]
        if r["pulled_by_sweep"] is not True:
            failed.append(f"{tag} was not pulled by the sweep (Gate 5 needs a model that "
                          "was not installed)")
        if r["deleted"] is not True:
            failed.append(f"{tag} was not deleted")
        if r["installed_after"] is not False:
            failed.append(f"{tag} is still installed after the sweep")
        if len(r["batches"]) != n_temperatures:
            failed.append(f"{tag} has {len(r['batches'])} batches, Gate 5 needs "
                          f"{n_temperatures} batches (one per temperature)")
        for b in r["batches"]:
            if not b.get("ok"):
                failed.append(f"{tag}: batch {b.get('batch_id')} is not ok in the record")
            failed += check_batch_folder(results_dir, b["batch_id"])
        if not sweep_record.is_done(sdir, tag):
            failed.append(f"{tag} completed but has no done marker")
        if f"{tag}: {SKIPPED}" not in log_text:
            failed.append(f"sweep.log does not show a second start skipping {tag}")
    for r in records:
        if r["status"] != "completed" and sweep_record.is_done(sdir, r["tag"]):
            failed.append(f"{r['tag']} has a done marker with status {r['status']}")
    for r in pull_failed:
        if r["deleted"] or r["batches"]:
            failed.append(f"{r['tag']} failed to pull but has batches or a delete")
    return failed


def run_gate(ev: Evidence, cfg: dict, sweep_id: str) -> str | None:
    results_dir = _abs(cfg["results_dir"])
    sdir = sweep_record.sweep_dir(results_dir, sweep_id)
    out(ev, f"Gate 5 sweep: {sweep_id}")
    out(ev, f"record: {os.path.join(sdir, 'sweep.json')}")
    records = sweep_record.read_records(sdir)
    if not records:
        return f"no sweep record found for {sweep_id}"
    for r in records:
        show(ev, r["tag"], {k: v for k, v in r.items() if k != "batches"})
        for b in r["batches"]:
            out(ev, f"    batch {b['batch_id']}: ok={b['ok']} valid={b['valid']} "
                    f"invalid={b['invalid']} reason={b['reason']}")
    log_path = os.path.join(sdir, "sweep.log")
    log_text = ""
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as f:
            log_text = f.read()
    out(ev, "")
    out(ev, "sweep.log lines showing a skip on a later start:")
    for line in log_text.splitlines():
        if SKIPPED in line:
            out(ev, "  " + line)
    done_dir = os.path.join(sdir, "done")
    markers = sorted(os.listdir(done_dir)) if os.path.isdir(done_dir) else []
    out(ev, f"done markers: {', '.join(markers) or 'none'}")
    failed = check_sweep(records, sdir, results_dir, len(cfg["temperatures"]), log_text)
    ev.data.update(sweep_id=sweep_id, records=records, markers=markers, failures=failed)
    out(ev, "")
    out(ev, "Limitations:")
    out(ev, f"- {sweep_record.LIMITATION}")
    out(ev, "")
    out(ev, VERBATIM)
    return "; ".join(failed) if failed else None


def body(ev: Evidence, argv: list[str] | None = None) -> str | None:
    p = argparse.ArgumentParser(description="Gate 5: the model sweep.")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--sweep-id", required=True)
    args = p.parse_args(argv)
    cfg = load_config(_abs(args.config))
    return run_gate(ev, cfg, args.sweep_id)


def main(argv: list[str] | None = None) -> int:
    return run_main("gate5", lambda ev: body(ev, argv))


if __name__ == "__main__":
    sys.exit(main())
