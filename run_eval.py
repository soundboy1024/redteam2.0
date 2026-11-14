"""Batch CLI: wires harness, listener process, run log, grader and results writer.

Usage: .venv/Scripts/python.exe run_eval.py [--config config.yaml] [--models a,b]
       [--scenarios id,id] [--n-runs N] [--telemetry|--no-telemetry] [--batch-id ID]
"""
import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from functools import partial
from typing import Callable

from harness import ollama_client
from harness.runner import load_scenarios, run_one
from listener_proc import start_listener, stop_listener
from rt_config import ConfigError, load_config
from telemetry.grader import grade_batch
from telemetry.logger import (JSONL_FILES, log_run, log_step, log_tool_event,
                              open_batch, read_steps, read_tool_events)
from telemetry.report import (write_results_json, write_summary_md,
                              write_transcript_md)
from traps.events_db import fetch_events
from traps.validate_scenarios import validate

log = logging.getLogger(__name__)
ROOT = os.path.dirname(os.path.abspath(__file__))
SCENARIOS_PATH = os.path.join(ROOT, "traps", "scenarios.json")
FIXTURES_ROOT = os.path.join(ROOT, "traps", "fixtures")


class LogWriteError(RuntimeError):
    """The run log could not be written. Not caught by run_one: the batch aborts."""


class ListenerStartError(RuntimeError):
    """The decoy listener could not be started (for example the port is in use)."""


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _guard(fn: Callable) -> Callable:
    """Re-raise any logger failure as LogWriteError so run_one cannot mistake a
    ValueError from the log for an infrastructure failure of the run."""
    def wrapped(*args):
        try:
            return fn(*args)
        except Exception as exc:
            raise LogWriteError(f"run log write failed: {type(exc).__name__}: {exc}") from exc
    return wrapped


def _default_chat_fn_factory(cfg: dict, telemetry: bool) -> Callable:
    def factory(model: str, repetition_index: int):
        return partial(ollama_client.chat, cfg["ollama_host"], model,
                       temperature=cfg["temperature"], seed=repetition_index,
                       num_ctx=cfg["num_ctx"], num_predict=cfg["num_predict"],
                       telemetry=telemetry, timeout_s=cfg["ollama_timeout_s"])
    return factory


def _write_results(cfg, batch_log, batch_id, scenarios, meta):
    results = grade_batch(cfg["db_path"], cfg["listener_db_path"], batch_id,
                          scenarios, cfg["canaries"])
    write_results_json(batch_log.out_dir, meta, results)
    write_summary_md(batch_log.out_dir, meta, results)
    for r in results:
        write_transcript_md(
            batch_log.out_dir, r, read_steps(cfg["db_path"], r["run_id"]),
            read_tool_events(cfg["db_path"], r["run_id"]),
            fetch_events(cfg["listener_db_path"], r["run_id"]))
    return results


def _remove_empty_batch(batch_log) -> None:
    """Undo open_batch after a failed listener start, if nothing was written."""
    try:
        names = sorted(os.listdir(batch_log.out_dir))
        if names != sorted(JSONL_FILES) or any(
                os.path.getsize(os.path.join(batch_log.out_dir, n)) for n in names):
            return
        for n in names:
            os.remove(os.path.join(batch_log.out_dir, n))
        os.rmdir(batch_log.out_dir)
    except OSError:
        log.error("could not remove empty batch folder %s", batch_log.out_dir, exc_info=True)


def run_batch(cfg: dict, models: list[str], scenario_ids: list[str], n_runs: int,
              telemetry: bool, batch_id: str, chat_fn_factory: Callable | None = None,
              *, config_path: str, scenarios_path: str = SCENARIOS_PATH,
              fixtures_root: str = FIXTURES_ROOT) -> dict:
    file_cfg = load_config(config_path)
    for key in ("canaries", "listener"):
        if file_cfg[key] != cfg[key]:
            raise ValueError(f"cfg and {config_path} disagree on '{key}'; the listener "
                             "would scan with different settings than the grader uses")
    scenarios = load_scenarios(scenarios_path)
    by_id = {s["id"]: s for s in scenarios}
    chosen = [by_id[i] for i in scenario_ids]  # KeyError on an unknown id
    factory = chat_fn_factory or _default_chat_fn_factory(cfg, telemetry)
    # Before anything is launched, so a bad or reused batch id fails first.
    batch_log = open_batch(cfg["db_path"], cfg["results_dir"], batch_id)
    step_sink = _guard(lambda row: log_step(batch_log, row))
    event_sink = _guard(lambda run_id, ev: log_tool_event(batch_log, run_id, ev))
    record_run = _guard(lambda rec: log_run(batch_log, rec))
    started_at = datetime.now(timezone.utc).isoformat()
    aborted, consecutive = False, 0
    host, port = cfg["listener"]["host"], cfg["listener"]["port"]
    try:
        proc = start_listener(os.path.abspath(config_path),
                              os.path.abspath(cfg["listener_db_path"]), host, port)
    except RuntimeError as exc:
        _remove_empty_batch(batch_log)
        raise ListenerStartError(str(exc)) from exc
    try:
        for model in models:
            for scenario in chosen:
                for rep in range(n_runs):
                    record = run_one(scenario, fixtures_root, model, rep, cfg,
                                     batch_id=batch_id, telemetry=telemetry,
                                     chat_fn=factory(model, rep),
                                     step_sink=step_sink, event_sink=event_sink)
                    record_run(record)
                    consecutive = consecutive + 1 if record["status"] == "invalid" else 0
                    if consecutive >= cfg["max_consecutive_invalid"]:
                        aborted = True
                        log.error("aborting batch %s: %d consecutive invalid runs",
                                  batch_id, consecutive)
                        break
                if aborted:
                    break
            if aborted:
                break
    finally:
        stop_listener(proc)
    meta = {"batch_id": batch_id, "models": list(models),
            "scenario_ids": list(scenario_ids), "n_runs": n_runs,
            "temperature": cfg["temperature"], "telemetry_enabled": telemetry,
            "started_at": started_at, "ended_at": datetime.now(timezone.utc).isoformat(),
            "aborted": aborted}
    results = _write_results(cfg, batch_log, batch_id, scenarios, meta)
    return {"batch_id": batch_id, "out_dir": batch_log.out_dir, "results": results,
            "aborted": aborted}


def _csv(text: str) -> list[str]:
    return [p.strip() for p in text.split(",") if p.strip()]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run a red-team evaluation batch.")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--models", help="comma list; default from config")
    p.add_argument("--scenarios", help="comma list of scenario ids; default all")
    p.add_argument("--n-runs", type=int)
    p.add_argument("--telemetry", dest="telemetry", action="store_true", default=None)
    p.add_argument("--no-telemetry", dest="telemetry", action="store_false")
    p.add_argument("--batch-id", default=None)
    p.add_argument("--allow-any-model", action="store_true",
                   help="accept a model name that is not in config.yaml")
    return p


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        return _fail(f"config: {exc}")
    problems = validate(SCENARIOS_PATH, args.config)
    if problems:
        return _fail("scenarios invalid:\n  " + "\n  ".join(problems))
    all_ids = [s["id"] for s in load_scenarios(SCENARIOS_PATH)]
    scenario_ids = all_ids if args.scenarios is None else _csv(args.scenarios)
    if not scenario_ids:
        return _fail("--scenarios is empty; give scenario ids or omit the flag")
    unknown = [i for i in scenario_ids if i not in all_ids]
    if unknown:
        return _fail(f"unknown scenario(s) {unknown}; known: {all_ids}")
    models = list(cfg["models"]) if args.models is None else _csv(args.models)
    if not models:
        return _fail("--models is empty; give model names or omit the flag")
    bad_models = [m for m in models if m not in cfg["models"]]
    if bad_models and not args.allow_any_model:
        return _fail(f"unknown model(s) {bad_models}; configured: "
                     f"{cfg['models']} (use --allow-any-model to override)")
    n_runs = args.n_runs if args.n_runs is not None else cfg["n_runs"]
    if n_runs < 1:
        return _fail("--n-runs must be at least 1")
    telemetry = cfg["telemetry_enabled"] if args.telemetry is None else args.telemetry
    batch_id = args.batch_id or _utc_stamp()
    try:
        out = run_batch(cfg, models, scenario_ids, n_runs, telemetry, batch_id,
                        config_path=args.config)
    except (ListenerStartError, LogWriteError, ValueError) as exc:
        return _fail(str(exc))
    print(f"summary: {os.path.join(out['out_dir'], 'summary.md')}")
    for r in out["results"]:
        print(f"{r['scenario_id']} {r['model_name']} rep={r['repetition_index']} {r['cell']}")
    if out["aborted"]:
        return _fail(f"batch {batch_id} aborted after consecutive invalid runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
