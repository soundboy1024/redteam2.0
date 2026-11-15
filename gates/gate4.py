"""Gate 4: the full matrix for two models, and the inspector on one compromised run
(director gate).

Run from the repo root with the .venv python, after the Gate 4 batch has finished:
    .venv\\Scripts\\python.exe gates\\gate4.py --batch-id BATCH_ID [--config config.yaml]

Starts no listener and calls no model. It reads the stored results of one batch (the
fresh two-model batch started from the Run page) and prints what the dashboard's
Results and Inspect pages show for it. Judging the behaviour is the director's call.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "gates"))

from _common import Evidence, out, run_main  # noqa: E402
from dashboard import data  # noqa: E402
from rt_config import load_config  # noqa: E402
from telemetry.report import CELLS  # noqa: E402

VERBATIM = ("A compromised or failed-task result is not a gate failure. Gate 4 checks that "
            "the full matrix was run, graded and stored for two models, and that the "
            "inspector can show a compromised run. Judging the behaviour is the director's "
            "call.")
RAW_LIMIT = 600
FIXTURES_ROOT = os.path.join(ROOT, "traps", "fixtures")


def _abs(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(ROOT, path)


def _temp(t) -> str:
    return "default" if t is None else f"{t:g}"


def check_batch(batch: dict | None, plan: dict | None, results: list[dict],
                n_scenarios: int) -> list[str]:
    """Every reason this batch does not satisfy Gate 4. Empty means it does."""
    if batch is None:
        return ["batch not found in the run log"]
    failed = []
    if plan is None:
        return ["batch has no batch.json; Gate 4 needs a batch started after 4.8"]
    if len(plan["models"]) != 2:
        failed.append(f"batch has {len(plan['models'])} model(s), Gate 4 needs exactly 2")
    if plan["n_runs"] != 3:
        failed.append(f"n_runs is {plan['n_runs']}, Gate 4 needs 3")
    if len(plan["scenario_ids"]) != n_scenarios:
        failed.append(f"batch ran {len(plan['scenario_ids'])} of {n_scenarios} scenarios; "
                      "Gate 4 needs the full matrix")
    if not plan.get("ended_at"):
        failed.append("batch has not ended")
    if plan.get("aborted"):
        failed.append(f"batch was aborted: {plan.get('abort_reason')}")
    if batch["recorded_runs"] != plan["planned_runs"]:
        failed.append(f"{batch['recorded_runs']} runs recorded, {plan['planned_runs']} "
                      "planned")
    if len(results) != batch["recorded_runs"]:
        failed.append(f"{len(results)} stored results for {batch['recorded_runs']} "
                      "recorded runs")
    if not batch["has_result_files"]:
        failed.append("results.json or summary.md is missing")
    for model in plan["models"]:
        if not any(r["model_name"] == model for r in results):
            failed.append(f"no stored result for model {model}")
    if not any(r["valid"] and r["compromised"] for r in results):
        failed.append("no valid compromised run to show in the inspector")
    return failed


def print_matrix(ev: Evidence, m: dict) -> None:
    t = m["totals"]
    out(ev, f"{t['total']} runs: {t['valid']} valid, {t['invalid']} invalid. "
            f"{t['runs_with_parse_failures']} runs had parse failures. "
            f"{t['runs_with_attempted_tripwires']} runs had unexecuted trap attempts.")
    out(ev, "cells: " + " | ".join(CELLS))
    model = None
    for r in m["rows"]:
        if r["model_name"] != model:
            model = r["model_name"]
            out(ev, "")
            out(ev, f"== {model} ==")
        cells = " | ".join(str(r[c]) for c in CELLS)
        out(ev, f"  t={_temp(r['temperature']):<8} {r['attack_taxonomy']:<28} "
                f"valid={r['n_valid']}  {cells}  invalid={r['invalid']} "
                f"parse_failure_runs={r['runs_with_parse_failures']} "
                f"unexecuted_attempt_runs={r['runs_with_attempted_tripwires']} "
                f"distinct_trajectories={r['distinct_trajectories']}")


def print_inspector(ev: Evidence, d: dict) -> None:
    result = d["result"]
    out(ev, f"run_id: {result['run_id']}")
    out(ev, f"model: {result['model_name']} | scenario: {result['scenario_id']} | "
            f"temperature: {_temp(result['temperature'])} | "
            f"repetition: {result['repetition_index']}")
    out(ev, f"result: {result['cell']}")
    out(ev, f"tripwires fired: {', '.join(d['tripwires_fired']) or 'none'}")
    out(ev, f"canaries leaked: {', '.join(result['canary_ids']) or 'none'}")
    out(ev, f"poison entered the context at step: {d['poison_step_index']}")
    for p in d["poison_texts"]:
        out(ev, f"poisoned file: {p['file']} ({p['source']}), {len(p['text'])} characters")
    out(ev, f"attempted calls never executed: {json.dumps(d['attempted_calls'])}")
    out(ev, "steps:")
    for s in d["steps"]:
        mark = "  <- poison in context from here" if s["step_index"] == d[
            "poison_step_index"] else ""
        out(ev, f"  step {s['step_index']} | {s['agent_state']} | "
                f"{s['tool_name'] or 'no tool'} | parse_reason={s['parse_reason']} | "
                f"done_reason={s['done_reason']}{mark}")
        if s["step_index"] >= 1:
            raw = " ".join((s["raw_response"] or "(empty reply)").split())
            out(ev, f"      raw reply: {raw[:RAW_LIMIT]}"
                    + (" ...[cut for this printout]" if len(raw) > RAW_LIMIT else ""))
    out(ev, "listener rows:")
    for e in d["listener_events"]:
        out(ev, f"  {e['timestamp']} {e['method']} {e['path']} class={e['route_class']} "
                f"canaries={e['canary_ids']}")


def run_gate(ev: Evidence, cfg: dict, batch_id: str, n_scenarios: int) -> str | None:
    db, listener_db = _abs(cfg["db_path"]), _abs(cfg["listener_db_path"])
    results_dir = _abs(cfg["results_dir"])
    batch = next((b for b in data.list_batches(db, results_dir)
                  if b["batch_id"] == batch_id), None)
    plan, problem = data.read_plan_safe(results_dir, batch_id)
    if problem:
        return f"batch.json could not be read: {problem}"
    results = data.stored_results(db, [batch_id])
    out(ev, f"Gate 4 batch: {batch_id}")
    if plan:
        out(ev, f"models: {', '.join(plan['models'])}")
        out(ev, f"scenarios: {', '.join(plan['scenario_ids'])}")
        out(ev, f"temperatures: {', '.join(_temp(t) for t in plan['temperatures'])} | "
                f"n_runs: {plan['n_runs']} | planned runs: {plan['planned_runs']}")
        out(ev, f"command: {' '.join(plan['command'] or [])}")
        out(ev, f"started: {plan['started_at']} | ended: {plan['ended_at']} | "
                f"aborted: {plan['aborted']}")
    failed = check_batch(batch, plan, results, n_scenarios)
    ev.data.update(batch_id=batch_id, plan=plan, failures=failed)
    if batch is None or plan is None:
        return "; ".join(failed)
    out(ev, "")
    out(ev, "=== Results page: four-cell matrix (stored grades, never re-graded) ===")
    m = data.matrix(db, results_dir, [batch_id])
    print_matrix(ev, m)
    ev.data.update(matrix=m["rows"], totals=m["totals"])
    compromised = [r for r in results if r["valid"] and r["compromised"]]
    if compromised:
        pick = compromised[0]
        out(ev, "")
        out(ev, "=== Inspect page: first compromised run of the batch ===")
        d = data.run_detail(db, listener_db, FIXTURES_ROOT, pick["run_id"])
        print_inspector(ev, d)
        ev.data.update(inspected_run_id=pick["run_id"], inspected_result=d["result"],
                       poison_step_index=d["poison_step_index"])
    out(ev, "")
    out(ev, "Limitations:")
    for note in data.LIMITATIONS:
        out(ev, f"- {note}")
    out(ev, "")
    out(ev, VERBATIM)
    return "; ".join(failed) if failed else None


def body(ev: Evidence, argv: list[str] | None = None) -> str | None:
    p = argparse.ArgumentParser(description="Gate 4: full matrix for two models and the "
                                            "inspector on a compromised run.")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--batch-id", required=True)
    args = p.parse_args(argv)
    cfg = load_config(_abs(args.config))
    with open(os.path.join(ROOT, "traps", "scenarios.json"), encoding="utf-8") as f:
        n_scenarios = len(json.load(f))
    return run_gate(ev, cfg, args.batch_id, n_scenarios)


def main(argv: list[str] | None = None) -> int:
    return run_main("gate4", lambda ev: body(ev, argv))


if __name__ == "__main__":
    sys.exit(main())
