"""Batch CLI: wires harness, listener process, run log, grader and results writer.

Usage: .venv/Scripts/python.exe run_eval.py [--config config.yaml] [--models a,b]
       [--scenarios id,id] [--n-runs N] [--temperatures 0.1,0.3] [--telemetry|--no-telemetry] [--batch-id ID]
"""
import argparse
import logging
import math
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from typing import Callable

from batch_results import LogWriteError, write_batch_results
from harness import ollama_client
from harness.agent_loop import SYSTEM_PROMPT
from harness.runner import load_scenarios, run_one
from listener_proc import start_listener, stop_listener
from rt_config import ConfigError, load_config
from telemetry.logger import (JSONL_FILES, log_run, log_run_inputs, log_step,
                              log_tool_event, open_batch)
from traps.validate_scenarios import validate

log = logging.getLogger(__name__)
ROOT = os.path.dirname(os.path.abspath(__file__))
SCENARIOS_PATH = os.path.join(ROOT, "traps", "scenarios.json")
FIXTURES_ROOT = os.path.join(ROOT, "traps", "fixtures")
CONSECUTIVE_INVALID = "consecutive invalid runs"


class ListenerStartError(RuntimeError):
    """The decoy listener could not be started (for example the port is in use)."""


@dataclass
class PreparedBatch:
    cfg: dict
    config_path: str
    batch_log: object       # telemetry.logger.BatchLog
    scenarios: list         # every scenario, for the grader
    chosen: list            # the scenarios this batch runs
    models: list
    scenario_ids: list
    n_runs: int
    telemetry: bool
    temperatures: list
    factory: Callable
    fixtures_root: str


def temperatures_for(model: str, temperatures: list) -> list:
    """The temperatures a model is run at. Every model takes them all for now."""
    return list(temperatures)


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    def factory(model: str, repetition_index: int, temperature: float | None):
        return partial(ollama_client.chat, cfg["ollama_host"], model,
                       temperature=temperature, seed=repetition_index,
                       num_ctx=cfg["num_ctx"], num_predict=cfg["num_predict"],
                       telemetry=telemetry, timeout_s=cfg["ollama_timeout_s"])
    return factory


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


def prepare_batch(cfg: dict, models: list[str], scenario_ids: list[str], n_runs: int,
                  telemetry: bool, batch_id: str, chat_fn_factory: Callable | None = None,
                  *, temperatures: list, config_path: str,
                  scenarios_path: str = SCENARIOS_PATH,
                  fixtures_root: str = FIXTURES_ROOT) -> PreparedBatch:
    """Config check and batch opening: everything that may fail before a run starts."""
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
    return PreparedBatch(cfg, config_path, batch_log, scenarios, chosen, list(models),
                         list(scenario_ids), n_runs, telemetry, list(temperatures), factory,
                         fixtures_root)


def _run_all(prep: PreparedBatch, state: dict) -> None:
    """Every run of the batch, in order. Updates state as runs are recorded."""
    cfg, batch_log = prep.cfg, prep.batch_log
    current: dict = {}
    inputs_logged: set[str] = set()

    def log_inputs(run_id: str) -> None:  # once per run, before its first row
        if run_id not in inputs_logged:
            sc = current["scenario"]
            log_run_inputs(batch_log, run_id, sc["user_prompt"], SYSTEM_PROMPT, sc)
            inputs_logged.add(run_id)

    def step(row: dict) -> None:
        log_inputs(row["run_id"])
        log_step(batch_log, row)

    def record(rec: dict) -> None:
        log_inputs(rec["run_id"])  # a run that failed before step 0 has no rows
        log_run(batch_log, rec)

    step_sink, record_run = _guard(step), _guard(record)
    event_sink = _guard(lambda run_id, ev: log_tool_event(batch_log, run_id, ev))
    consecutive = 0
    for model in prep.models:
        for scenario in prep.chosen:
            for temperature in temperatures_for(model, prep.temperatures):
                for rep in range(prep.n_runs):
                    current["scenario"] = scenario
                    rec = run_one(scenario, prep.fixtures_root, model, rep, cfg,
                                  temperature=temperature,
                                  batch_id=batch_log.batch_id, telemetry=prep.telemetry,
                                  chat_fn=prep.factory(model, rep, temperature),
                                  step_sink=step_sink, event_sink=event_sink)
                    record_run(rec)
                    state["recorded"] += 1
                    consecutive = consecutive + 1 if rec["status"] == "invalid" else 0
                    if consecutive >= cfg["max_consecutive_invalid"]:
                        log.error("aborting batch %s: %d consecutive invalid runs",
                                  batch_log.batch_id, consecutive)
                        state["aborted"], state["abort_reason"] = True, CONSECUTIVE_INVALID
                        return


def _stop(proc, error: BaseException | None) -> Exception | None:
    """Stop the listener. A failure is logged and returned, never raised here, so it
    cannot mask an exception already in flight."""
    try:
        stop_listener(proc)
    except Exception as exc:
        log.exception("could not stop the listener")
        if error is not None:
            log.error("the batch was already failing with %s: %s", type(error).__name__, error)
        return exc
    return None


def execute_batch(prep: PreparedBatch) -> dict:
    cfg, batch_log = prep.cfg, prep.batch_log
    host, port = cfg["listener"]["host"], cfg["listener"]["port"]
    try:
        proc = start_listener(os.path.abspath(prep.config_path),
                              os.path.abspath(cfg["listener_db_path"]), host, port)
    except RuntimeError as exc:
        _remove_empty_batch(batch_log)
        raise ListenerStartError(str(exc)) from exc
    started_at = _now()
    state = {"recorded": 0, "aborted": False, "abort_reason": None}
    error = None
    try:
        _run_all(prep, state)
    except BaseException as exc:  # held, results written below, then re-raised
        error = exc
        state["aborted"], state["abort_reason"] = True, f"{type(exc).__name__}: {exc}"
        log.error("batch %s aborted: %s", batch_log.batch_id, state["abort_reason"])
    stop_error = _stop(proc, error)
    meta = {"batch_id": batch_log.batch_id, "models": prep.models,
            "scenario_ids": prep.scenario_ids, "n_runs": prep.n_runs,
            "temperatures": prep.temperatures, "telemetry_enabled": prep.telemetry,
            "started_at": started_at, "ended_at": _now(), "aborted": state["aborted"],
            "abort_reason": state["abort_reason"]}
    if error is None:
        results = write_batch_results(cfg, batch_log, prep.scenarios, meta)
        if stop_error is not None:
            raise stop_error
        return {"batch_id": batch_log.batch_id, "out_dir": batch_log.out_dir,
                "results": results, "aborted": state["aborted"],
                "abort_reason": state["abort_reason"]}
    if state["recorded"]:
        try:
            write_batch_results(cfg, batch_log, prep.scenarios, meta)
        except Exception:
            log.exception("batch %s: grading or writing results failed after the abort "
                          "(%s); the original error is re-raised", batch_log.batch_id,
                          state["abort_reason"])
    raise error


def run_batch(cfg: dict, models: list[str], scenario_ids: list[str], n_runs: int,
              telemetry: bool, batch_id: str, chat_fn_factory: Callable | None = None,
              *, temperatures: list, config_path: str,
              scenarios_path: str = SCENARIOS_PATH,
              fixtures_root: str = FIXTURES_ROOT) -> dict:
    return execute_batch(prepare_batch(
        cfg, models, scenario_ids, n_runs, telemetry, batch_id, chat_fn_factory,
        temperatures=temperatures, config_path=config_path,
        scenarios_path=scenarios_path, fixtures_root=fixtures_root))


def _csv(text: str) -> list[str]:
    return [p.strip() for p in text.split(",") if p.strip()]


def _parse_temperatures(text: str) -> list[float]:
    """'0.1,0.3' to [0.1, 0.3]. Raises ValueError with a clear message."""
    parts = _csv(text)
    if not parts:
        raise ValueError("--temperatures is empty; give numbers like 0.1,0.3 or omit the flag")
    values = []
    for p in parts:
        try:
            v = float(p)
        except ValueError:
            raise ValueError(f"--temperatures: {p!r} is not a number") from None
        if not math.isfinite(v) or not 0 <= v <= 2:
            raise ValueError(f"--temperatures: {p!r} is outside 0 to 2")
        values.append(v)
    if len(set(values)) != len(values):
        raise ValueError(f"--temperatures has duplicates: {text!r}")
    return values


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run a red-team evaluation batch.")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--models", help="comma list; default from config")
    p.add_argument("--scenarios", help="comma list of scenario ids; default all")
    p.add_argument("--n-runs", type=int)
    p.add_argument("--temperatures", help="comma list, each 0 to 2; default from config")
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
    try:
        temperatures = (list(cfg["temperatures"]) if args.temperatures is None
                        else _parse_temperatures(args.temperatures))
    except ValueError as exc:
        return _fail(str(exc))
    telemetry = cfg["telemetry_enabled"] if args.telemetry is None else args.telemetry
    batch_id = args.batch_id or _utc_stamp()
    try:
        prep = prepare_batch(cfg, models, scenario_ids, n_runs, telemetry, batch_id,
                             temperatures=temperatures, config_path=args.config)
    except ValueError as exc:
        return _fail(str(exc))
    try:
        out = execute_batch(prep)
    except ListenerStartError as exc:
        return _fail(str(exc))
    except Exception as exc:  # a late failure: reported with its traceback, exit 1
        log.exception("batch %s failed", batch_id)
        return _fail(f"batch {batch_id} failed ({type(exc).__name__}: {exc}); "
                     f"output folder: {prep.batch_log.out_dir}")
    print(f"summary: {os.path.join(out['out_dir'], 'summary.md')}")
    for r in out["results"]:
        print(f"{r['scenario_id']} {r['model_name']} rep={r['repetition_index']} {r['cell']}")
    if out["aborted"]:
        return _fail(f"batch {batch_id} aborted: {out['abort_reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
