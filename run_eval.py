"""Batch CLI: wires harness, listener process, run log, grader and results writer.

Usage: .venv/Scripts/python.exe run_eval.py [--config config.yaml] [--models a,b]
       [--scenarios id,id] [--n-runs N] [--temperatures 0.1,0.3] [--defenses none,id]
       [--telemetry|--no-telemetry] [--batch-id ID]
       .venv/Scripts/python.exe run_eval.py <the same flags> --plan
       .venv/Scripts/python.exe run_eval.py --regrade BATCH_ID
       .venv/Scripts/python.exe run_eval.py --resume BATCH_ID
       .venv/Scripts/python.exe run_eval.py --list-remote-models anthropic|groq|cerebras|google
"""
import argparse
import json
import logging
import math
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import partial
from typing import Callable

import batch_plan
import sweep_probe
from batch_results import (LogWriteError, grade_and_store_run,
                           write_batch_results)
from harness import ollama_client, remote_client
from harness.runner import NO_DEFENSE, defense_system_prompt, load_scenarios, run_one
from listener_proc import start_listener, stop_listener
from rt_config import ConfigError, load_config, resolve_defenses
from telemetry.logger import (JSONL_FILES, check_new_batch_id, existing_batch, log_run, log_run_inputs,
                              log_step, log_tool_event, open_batch, read_result_rows,
                              read_run_inputs, read_runs, read_step_run_ids)
from traps.validate_scenarios import validate

log = logging.getLogger(__name__)
ROOT = os.path.dirname(os.path.abspath(__file__))
SCENARIOS_PATH = os.path.join(ROOT, "traps", "scenarios.json")
FIXTURES_ROOT = os.path.join(ROOT, "traps", "fixtures")
CONSECUTIVE_INVALID = "consecutive invalid runs"
LOW_MEMORY = "free memory under the floor"
GB = 2 ** 30
DIGEST_TIMEOUT_S = 10


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
    defenses: list          # defense entries (dicts), in run order
    free_memory_fn: Callable | None = None   # bytes free; None turns the guard off
    stop_free_memory_gb: float = 0.0         # 0 turns the guard off
    skip: frozenset = frozenset()            # run slots already recorded (a resume)
    resumed: list = field(default_factory=list)       # one entry per resume, oldest first
    batch_notes: list = field(default_factory=list)   # added to the summary's notes
    model_digests: dict = field(default_factory=dict)  # local model name to digest or None


def temperatures_for(model: str, temperatures: list) -> list:
    """The temperatures a model is run at. A model that rejects a temperature setting
    runs once per repetition with none (None, shown as "default")."""
    if not remote_client.accepts_temperature(model):
        return [None]
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


def _hosted_chat_fn(cfg: dict, model: str, seed: int, temperature: float | None,
                    api_key: str) -> Callable:
    """A closure, not a partial: its repr never shows the key."""
    def chat_fn(messages: list[dict]):
        return remote_client.chat(model, messages, temperature=temperature, seed=seed,
                                  max_tokens=cfg["remote_max_tokens"],
                                  timeout_s=cfg["remote_timeout_s"], api_key=api_key)
    return chat_fn


def _default_chat_fn_factory(cfg: dict, telemetry: bool) -> Callable:
    def factory(model: str, repetition_index: int, temperature: float | None):
        provider, _ = remote_client.split_model(model)
        if provider is not None:
            if telemetry:
                raise ValueError(f"telemetry is local-only; refusing hosted model {model!r}")
            var = remote_client.PROVIDERS[provider]["key_env"]
            key = os.environ.get(var, "")
            defect = _key_defect(key)
            if defect:
                raise ValueError(f"environment variable {var} {defect}")
            return _hosted_chat_fn(cfg, model, repetition_index, temperature, key)
        if temperature is None:
            raise ValueError(f"local model {model!r} was given no temperature; only hosted "
                             "models that reject one may run without")
        return partial(ollama_client.chat, cfg["ollama_host"], model,
                       temperature=temperature, seed=repetition_index,
                       num_ctx=cfg["num_ctx"], num_predict=cfg["num_predict"],
                       telemetry=telemetry, timeout_s=cfg["ollama_timeout_s"])
    return factory


def is_local(model: str) -> bool:
    return remote_client.split_model(model)[0] is None


def free_memory_bytes() -> int:
    """Free physical memory. One name here, so a test can replace it."""
    return sweep_probe.free_memory_bytes()


def model_digests(cfg: dict, models: list[str]) -> dict:
    """The installed build (Ollama digest) of each local model in the batch, or None
    for one that could not be read. A tag such as qwen2.5:7b can be updated in place;
    the digest says which build a batch actually ran. Never stops a batch: a failure
    is logged and recorded as null."""
    local = [m for m in models if is_local(m)]
    if not local:
        return {}
    try:
        data = sweep_probe._call("GET", cfg["ollama_host"], "/api/tags",
                                 timeout_s=DIGEST_TIMEOUT_S)
        names = {m["name"]: m.get("digest") for m in sweep_probe._models(data, "/api/tags")}
    except (sweep_probe.ProbeError, KeyError, TypeError) as exc:
        log.warning("could not read model builds from Ollama (%s: %s); recorded as null",
                    type(exc).__name__, exc)
        return {m: None for m in local}
    out = {}
    for m in local:
        spellings = [m, m + ":latest" if ":" not in m else m,
                     m[:-len(":latest")] if m.endswith(":latest") else m]
        out[m] = next((names[s] for s in spellings if names.get(s)), None)
        if out[m] is None:
            log.warning("model %s is not in Ollama's installed list; build recorded as null", m)
    return out


def memory_problem(models: list[str], floor_gb: float, free_memory_fn: Callable | None,
                   ) -> str | None:
    """Why a batch with local models must not run right now, or None (CLAUDE.md 4.11).
    Hosted-only batches load no model here and are not checked."""
    if not floor_gb or free_memory_fn is None or not any(is_local(m) for m in models):
        return None
    free = free_memory_fn() / GB
    if free < floor_gb:
        return f"{LOW_MEMORY}: {free:.1f} GB free, floor {floor_gb:g} GB"
    return None


def _remove_empty_batch(batch_log) -> None:
    """Undo open_batch after a failed listener start, if nothing was written."""
    try:
        names = sorted(n for n in os.listdir(batch_log.out_dir)
                       if n != batch_plan.PLAN_FILE)
        if names != sorted(JSONL_FILES) or any(
                os.path.getsize(os.path.join(batch_log.out_dir, n)) for n in names):
            return
        if os.path.exists(os.path.join(batch_log.out_dir, batch_plan.PLAN_FILE)):
            names.append(batch_plan.PLAN_FILE)
        for n in names:
            os.remove(os.path.join(batch_log.out_dir, n))
        os.rmdir(batch_log.out_dir)
    except OSError:
        log.error("could not remove empty batch folder %s", batch_log.out_dir, exc_info=True)


def prepare_batch(cfg: dict, models: list[str], scenario_ids: list[str], n_runs: int,
                  telemetry: bool, batch_id: str, chat_fn_factory: Callable | None = None,
                  *, temperatures: list, config_path: str,
                  scenarios_path: str = SCENARIOS_PATH,
                  fixtures_root: str = FIXTURES_ROOT,
                  command: list | None = None,
                  defense_ids: list | None = None,
                  free_memory_fn: Callable | None = None,
                  stop_free_memory_gb: float = 0.0,
                  digests: dict | None = None) -> PreparedBatch:
    """Config check and batch opening: everything that may fail before a run starts."""
    defense_ids = [NO_DEFENSE["id"]] if defense_ids is None else list(defense_ids)
    defenses = resolve_defenses(cfg, defense_ids)  # ValueError before anything opens
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
    digests = dict(digests or {})
    plan = _plan(batch_id, models, scenario_ids, temperatures, n_runs, telemetry, command,
                 defense_ids)
    plan["model_digests"] = digests
    batch_plan.write_plan(batch_log.out_dir, plan)
    return PreparedBatch(cfg, config_path, batch_log, scenarios, chosen, list(models),
                         list(scenario_ids), n_runs, telemetry, list(temperatures), factory,
                         fixtures_root, defenses, free_memory_fn=free_memory_fn,
                         stop_free_memory_gb=stop_free_memory_gb, model_digests=digests)


def _slot(model, scenario_id, defense_id, temperature, repetition_index) -> tuple:
    """One planned run: its place in the batch plan."""
    return (model, scenario_id, defense_id, temperature, repetition_index)


def _inputs_problem(cfg: dict, runs: list[dict], by_id: dict, defenses: dict) -> str | None:
    """Why the recorded runs of a batch no longer match what a resumed run would be
    given, or None. Compares each recorded run's stored inputs with today's scenario
    entry and system prompt."""
    for run in runs:
        stored = read_run_inputs(cfg["db_path"], run["run_id"])
        if stored is None:
            continue  # a run that failed before its inputs were logged
        scenario = by_id.get(run["scenario_id"])
        defense = defenses.get(run["defense_id"])
        if scenario is None or defense is None:
            return (f"run {run['run_id']} used scenario {run['scenario_id']!r} and defense "
                    f"{run['defense_id']!r}; one of them no longer exists")
        if stored["scenario"] != json.loads(json.dumps(scenario)):
            return (f"scenario {run['scenario_id']!r} has changed since run "
                    f"{run['run_id']} was recorded")
        if stored["system_prompt"] != defense_system_prompt(defense, cfg):
            return (f"the system prompt for defense {run['defense_id']!r} has changed "
                    f"since run {run['run_id']} was recorded")
    return None


def prepare_resume(cfg: dict, batch_id: str, chat_fn_factory: Callable | None = None, *,
                   config_path: str, scenarios_path: str = SCENARIOS_PATH,
                   fixtures_root: str = FIXTURES_ROOT,
                   free_memory_fn: Callable | None = None,
                   stop_free_memory_gb: float = 0.0,
                   digests_fn: Callable | None = None) -> PreparedBatch:
    """Everything that may fail before a stopped batch is taken up again (CLAUDE.md
    4.11). The selection comes from the batch's own batch.json, never from flags.
    Raises ValueError with the reason; changes nothing until it returns."""
    batch_log = existing_batch(cfg["db_path"], cfg["results_dir"], batch_id)
    plan = batch_plan.read_plan(batch_log.out_dir)
    if plan is None:
        raise ValueError(f"batch {batch_id!r} has no batch.json, so its plan is unknown; "
                         "it cannot be resumed")
    if _batch_process_alive(plan):
        raise ValueError(f"batch {batch_id!r} is still running (process {plan['pid']}); "
                         "resume it only after it has stopped")
    file_cfg = load_config(config_path)
    for key in ("canaries", "listener"):
        if file_cfg[key] != cfg[key]:
            raise ValueError(f"cfg and {config_path} disagree on '{key}'; the listener "
                             "would scan with different settings than the grader uses")
    models, scenario_ids = list(plan["models"]), list(plan["scenario_ids"])
    temperatures, n_runs = list(plan["temperatures"]), plan["n_runs"]
    telemetry = bool(plan["telemetry_enabled"])
    defense_ids = list(plan.get("defenses") or [NO_DEFENSE["id"]])
    defenses = resolve_defenses(cfg, defense_ids)
    scenarios = load_scenarios(scenarios_path)
    by_id = {s["id"]: s for s in scenarios}
    missing = [i for i in scenario_ids if i not in by_id]
    if missing:
        raise ValueError(f"batch {batch_id!r} planned scenario(s) {missing} that no longer "
                         "exist")
    for m in models:
        if temperatures_for(m, temperatures) != plan["temps_per_model"].get(m):
            raise ValueError(f"model {m!r} would now run at different temperatures than "
                             f"batch {batch_id!r} planned")
    runs = read_runs(cfg["db_path"], batch_id)
    problem = _inputs_problem(cfg, runs, by_id, {d["id"]: d for d in defenses})
    if problem:
        raise ValueError(f"batch {batch_id!r} cannot be resumed: {problem}. The new runs "
                         "would not be comparable with the recorded ones; start a new batch")
    done = frozenset(_slot(r["model_name"], r["scenario_id"], r["defense_id"],
                           r["temperature"], r["repetition_index"]) for r in runs)
    planned = [_slot(m, s, d, t, rep) for m in models for s in scenario_ids
               for d in defense_ids for t in temperatures_for(m, temperatures)
               for rep in range(n_runs)]
    remaining = [p for p in planned if p not in done]
    if not remaining:
        raise ValueError(f"every planned run of batch {batch_id!r} is already recorded; "
                         "nothing to resume (use --regrade if its files are missing)")
    recorded_digests = plan.get("model_digests") or {}
    todo_models = {p[0] for p in remaining}
    now_digests = (digests_fn or (lambda: {}))()
    for m in sorted(todo_models):
        before, now = recorded_digests.get(m), now_digests.get(m)
        if before and now and before != now:
            raise ValueError(f"batch {batch_id!r} cannot be resumed: model {m!r} is a "
                             "different build now than when the batch started (it was "
                             "updated or reinstalled); start a new batch")
    recorded = {r["run_id"] for r in runs}
    orphans = [i for i in read_step_run_ids(batch_log.out_dir) if i not in recorded]
    resumed = list(plan.get("resumed") or [])
    resumed.append({"at": _now(), "recorded_before": len(runs), "remaining": len(remaining)})
    notes = [f"steps logged for run {i} but the run was never recorded (cut off "
             "mid-run); it is in no cell" for i in orphans]
    notes.append(f"This batch was resumed {len(resumed)} time(s), so its runs were "
                 "recorded in more than one sitting: "
                 + "; ".join(f"{e['at']} with {e['recorded_before']} run(s) recorded and "
                             f"{e['remaining']} to go" for e in resumed) + ".")
    factory = chat_fn_factory or _default_chat_fn_factory(cfg, telemetry)
    return PreparedBatch(cfg, config_path, batch_log, scenarios,
                         [by_id[i] for i in scenario_ids], models, scenario_ids, n_runs,
                         telemetry, temperatures, factory, fixtures_root, defenses,
                         free_memory_fn=free_memory_fn,
                         stop_free_memory_gb=stop_free_memory_gb, skip=done,
                         resumed=resumed, batch_notes=notes,
                         model_digests=dict(recorded_digests))


def _plan(batch_id: str, models: list, scenario_ids: list, temperatures: list,
          n_runs: int, telemetry: bool, command: list | None,
          defense_ids: list | None = None) -> dict:
    return batch_plan.build_plan(
        batch_id, models, scenario_ids, temperatures, n_runs, telemetry,
        {m: temperatures_for(m, temperatures) for m in models}, command, defense_ids)


def _run_all(prep: PreparedBatch, state: dict) -> None:
    """Every run of the batch, in order. Updates state as runs are recorded."""
    cfg, batch_log = prep.cfg, prep.batch_log
    current: dict = {}
    inputs_logged: set[str] = set()

    def log_inputs(run_id: str) -> None:  # once per run, before its first row
        if run_id not in inputs_logged:
            sc = current["scenario"]
            log_run_inputs(batch_log, run_id, sc["user_prompt"],
                           defense_system_prompt(current["defense"], cfg), sc)
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
            for defense, temperature, rep in (
                    (d, t, r) for d in prep.defenses
                    for t in temperatures_for(model, prep.temperatures)
                    for r in range(prep.n_runs)):
                if _slot(model, scenario["id"], defense["id"], temperature,
                         rep) in prep.skip:
                    continue  # recorded before this resume
                low = memory_problem([model], prep.stop_free_memory_gb, prep.free_memory_fn)
                if low:
                    log.error("aborting batch %s: %s", batch_log.batch_id, low)
                    state["aborted"], state["abort_reason"] = True, low
                    return
                current["scenario"], current["defense"] = scenario, defense
                rec = run_one(scenario, prep.fixtures_root, model, rep, cfg,
                              temperature=temperature,
                              batch_id=batch_log.batch_id, telemetry=prep.telemetry,
                              chat_fn=prep.factory(model, rep, temperature),
                              step_sink=step_sink, event_sink=event_sink,
                              defense=defense)
                record_run(rec)
                state["recorded"] += 1
                # Stored now, so a live view has a grade to show (CLAUDE.md 4.8).
                # An invalid run waits for the end of the batch: after a listener
                # fault its listener row can still land late, and a stored row is
                # never corrected.
                if rec["status"] != "invalid":
                    grade_and_store_run(cfg, batch_log, prep.scenarios, rec["run_id"])
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
    try:  # inside the guarded block: a failure here must still stop the listener
        fields = {"pid": os.getpid(),
                  "pid_create_time": batch_plan.process_create_time(os.getpid())}
        if prep.resumed:   # the first start time stays; the end is open again
            fields.update(resumed=prep.resumed, ended_at=None, aborted=None,
                          abort_reason=None)
        else:
            fields["started_at"] = started_at
        batch_plan.update_plan(batch_log.out_dir, **fields)
        _run_all(prep, state)
    except BaseException as exc:  # held, results written below, then re-raised
        error = exc
        state["aborted"], state["abort_reason"] = True, f"{type(exc).__name__}: {exc}"
        log.error("batch %s aborted: %s", batch_log.batch_id, state["abort_reason"])
    stop_error = _stop(proc, error)
    meta = {"batch_id": batch_log.batch_id, "models": prep.models,
            "scenario_ids": prep.scenario_ids, "n_runs": prep.n_runs,
            "temperatures": prep.temperatures, "telemetry_enabled": prep.telemetry,
            "defenses": [d["id"] for d in prep.defenses],
            "hosted_models": [m for m in prep.models
                              if remote_client.split_model(m)[0] is not None],
            "models_without_temperature": [m for m in prep.models
                                           if not remote_client.accepts_temperature(m)],
            "started_at": started_at, "ended_at": _now(), "aborted": state["aborted"],
            "abort_reason": state["abort_reason"], "model_digests": prep.model_digests,
            "resumed": prep.resumed}
    if prep.resumed:
        first = (batch_plan.read_plan(batch_log.out_dir) or {}).get("started_at")
        meta["started_at"] = first or started_at
    notes = prep.batch_notes or None
    try:
        batch_plan.finalise_plan(batch_log.out_dir, meta["ended_at"], state["aborted"],
                                 state["abort_reason"])
    except Exception:  # logged; a plan file must never stop the results being written
        log.exception("batch %s: could not write the end of the batch to batch.json; "
                      "results are still written", batch_log.batch_id)
    if error is None:
        results = write_batch_results(cfg, batch_log, prep.scenarios, meta,
                                      batch_notes=notes)
        if stop_error is not None:
            raise stop_error
        return {"batch_id": batch_log.batch_id, "out_dir": batch_log.out_dir,
                "results": results, "aborted": state["aborted"],
                "abort_reason": state["abort_reason"]}
    if state["recorded"] or prep.resumed:
        try:
            write_batch_results(cfg, batch_log, prep.scenarios, meta, batch_notes=notes)
        except Exception:
            log.exception("batch %s: grading or writing results failed after the abort "
                          "(%s); the original error is re-raised", batch_log.batch_id,
                          state["abort_reason"])
    raise error


def run_batch(cfg: dict, models: list[str], scenario_ids: list[str], n_runs: int,
              telemetry: bool, batch_id: str, chat_fn_factory: Callable | None = None,
              *, temperatures: list, config_path: str,
              scenarios_path: str = SCENARIOS_PATH,
              fixtures_root: str = FIXTURES_ROOT,
              defense_ids: list | None = None) -> dict:
    return execute_batch(prepare_batch(
        cfg, models, scenario_ids, n_runs, telemetry, batch_id, chat_fn_factory,
        temperatures=temperatures, config_path=config_path,
        scenarios_path=scenarios_path, fixtures_root=fixtures_root,
        defense_ids=defense_ids))


REGRADE_STOPPED = "regraded after the batch stopped early"
REGRADE_UNKNOWN = "regraded; planned run count unknown"


def _distinct(values) -> list:
    out = []
    for v in values:
        if v not in out:
            out.append(v)
    return out


def _regrade_meta(batch_id: str, runs: list[dict], plan: dict | None) -> dict:
    """Batch metadata for a regrade: from batch.json when there is one, otherwise
    rebuilt from the run rows."""
    if plan is not None:
        base = {k: plan[k] for k in ("models", "scenario_ids", "n_runs", "temperatures",
                                     "telemetry_enabled")}
        base["defenses"] = plan.get("defenses") or _distinct(r["defense_id"] for r in runs)
        base["model_digests"] = plan.get("model_digests") or {}
        base["resumed"] = plan.get("resumed") or []
        if plan.get("aborted"):
            aborted, reason = True, plan.get("abort_reason")
        elif plan["planned_runs"] == len(runs):
            aborted, reason = False, None
        else:
            aborted, reason = True, REGRADE_STOPPED
    else:
        base = {"models": _distinct(r["model_name"] for r in runs),
                "scenario_ids": _distinct(r["scenario_id"] for r in runs),
                "n_runs": max(r["repetition_index"] for r in runs) + 1,
                "temperatures": _distinct(r["temperature"] for r in runs),
                "telemetry_enabled": runs[0]["telemetry_enabled"],
                "defenses": _distinct(r["defense_id"] for r in runs)}
        aborted, reason = True, REGRADE_UNKNOWN
    models = base["models"]
    return {"batch_id": batch_id, **base,
            "hosted_models": [m for m in models
                              if remote_client.split_model(m)[0] is not None],
            "models_without_temperature": [m for m in models
                                           if not remote_client.accepts_temperature(m)],
            "started_at": (plan or {}).get("started_at") or runs[0]["started_at"],
            "ended_at": (plan or {}).get("ended_at") or runs[-1]["ended_at"],
            "aborted": aborted, "abort_reason": reason, "regraded_at": _now()}


def _batch_process_alive(plan: dict) -> bool:
    """Is the process this plan records still alive. A plan with a creation time needs
    both pid and creation time to match; an older plan counts as alive only while it has
    not ended and its pid exists."""
    created = batch_plan.process_create_time(plan.get("pid"))
    if created is None:
        return False
    recorded = plan.get("pid_create_time")
    if recorded is None:
        return not plan.get("ended_at")
    return created == recorded


def regrade(cfg: dict, batch_id: str, scenarios: list[dict]) -> dict:
    """Complete a batch that was logged but not fully graded (CLAUDE.md 4.8). Starts no
    listener and calls no model. Stored result rows are kept, never overwritten."""
    batch_log = existing_batch(cfg["db_path"], cfg["results_dir"], batch_id)
    runs = read_runs(cfg["db_path"], batch_id)
    if not runs:
        raise ValueError(f"batch {batch_id!r} has no recorded runs; nothing to grade")
    stored = read_result_rows(cfg["db_path"], batch_id)
    files = all(os.path.isfile(os.path.join(batch_log.out_dir, n))
                for n in ("results.json", "summary.md"))
    if len(stored) == len(runs) and files:
        raise ValueError(f"every run of batch {batch_id!r} already has a stored result "
                         "and its files exist; nothing to regrade")
    plan = batch_plan.read_plan(batch_log.out_dir)
    if plan is not None and _batch_process_alive(plan):
        raise ValueError(f"batch {batch_id!r} is still running (process {plan['pid']}); "
                         "regrade it only after it has stopped")
    meta = _regrade_meta(batch_id, runs, plan)
    recorded = {r["run_id"] for r in runs}
    orphans = [i for i in read_step_run_ids(batch_log.out_dir) if i not in recorded]
    meta["orphan_run_ids"] = orphans
    notes = [f"steps logged for run {i} but the run was never recorded (cut off "
             "mid-run); it is in no cell" for i in orphans]
    results = write_batch_results(cfg, batch_log, scenarios, meta, batch_notes=notes)
    if plan is not None and not plan.get("ended_at"):
        batch_plan.finalise_plan(batch_log.out_dir, meta["ended_at"], meta["aborted"],
                                 meta["abort_reason"])
    return {"batch_id": batch_id, "out_dir": batch_log.out_dir, "results": results,
            "orphan_run_ids": orphans}


def _print_results(out: dict) -> None:
    print(f"summary: {os.path.join(out['out_dir'], 'summary.md')}")
    for r in out["results"]:
        print(f"{r['scenario_id']} {r['model_name']} rep={r['repetition_index']} {r['cell']}")


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
    p.add_argument("--defenses", help="comma list of defense ids from config; each scenario "
                                      "runs under each; default none (CLAUDE.md 4.10)")
    p.add_argument("--telemetry", dest="telemetry", action="store_true", default=None)
    p.add_argument("--no-telemetry", dest="telemetry", action="store_false")
    p.add_argument("--batch-id", default=None)
    p.add_argument("--list-remote-models", metavar="PROVIDER",
                   help="print the model ids a provider offers (needs its key) and exit")
    p.add_argument("--plan", action="store_true",
                   help="print the batch plan as JSON and exit; opens no batch")
    p.add_argument("--regrade", metavar="BATCH_ID",
                   help="grade the runs of a logged batch that have no stored result, "
                        "write its files and exit; starts no listener")
    p.add_argument("--resume", metavar="BATCH_ID",
                   help="run the planned runs of a stopped batch that were never "
                        "recorded, under the same batch id; takes no selection flags")
    p.add_argument("--stop-free-memory-gb", type=float, default=None,
                   help="stop a batch with a local model when free memory falls under "
                        "this many GB; 0 turns the check off; default from config")
    p.add_argument("--allow-any-model", action="store_true",
                   help="accept a model name that is not in config.yaml")
    return p


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def _key_defect(key: str | None) -> str | None:
    """What is wrong with a key's shape, or None. Never repeats the value."""
    if not key:
        return "is empty or not set"
    if any(c.isspace() or not c.isascii() or not c.isprintable() for c in key):
        return "contains whitespace, control or non-ASCII characters"
    return None


def hosted_problem(models: list[str], telemetry: bool, environ) -> str | None:
    """Why a batch with hosted models cannot start, or None. Names the variable, never a value."""
    hosted = [m for m in models if remote_client.split_model(m)[0] is not None]
    if not hosted:
        return None
    if telemetry:
        return (f"telemetry is local-only and cannot be used with hosted model(s) {hosted}; "
                "use --no-telemetry")
    for m in hosted:
        var = remote_client.PROVIDERS[remote_client.split_model(m)[0]]["key_env"]
        defect = _key_defect(environ.get(var))
        if defect:
            return f"environment variable {var} {defect} (needed for {m})"
    return None


def list_remote_models(provider: str, environ) -> int:
    if provider not in remote_client.PROVIDERS:
        return _fail(f"unknown provider {provider!r}; known: {sorted(remote_client.PROVIDERS)}")
    var = remote_client.PROVIDERS[provider]["key_env"]
    key = environ.get(var)
    defect = _key_defect(key)
    if defect:
        return _fail(f"environment variable {var} {defect}")
    try:
        ids = remote_client.list_models(provider, key)
    except remote_client.RemoteModelError as exc:
        return _fail(f"listing {provider} models failed: {exc}")
    for model_id in ids:
        print(model_id)
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        return _fail(f"config: {exc}")
    if args.list_remote_models is not None:
        return list_remote_models(args.list_remote_models, os.environ)
    problems = validate(SCENARIOS_PATH, args.config)
    if problems:
        return _fail("scenarios invalid:\n  " + "\n  ".join(problems))
    if args.regrade is not None:
        try:
            out = regrade(cfg, args.regrade, load_scenarios(SCENARIOS_PATH))
        except ValueError as exc:
            return _fail(str(exc))
        _print_results(out)
        for i in out["orphan_run_ids"]:
            print(f"orphan steps (run never recorded, in no cell): {i}")
        return 0
    floor = (cfg["batch_stop_free_memory_gb"] if args.stop_free_memory_gb is None
             else args.stop_free_memory_gb)
    if not math.isfinite(floor) or floor < 0:
        return _fail("--stop-free-memory-gb must be 0 or more")
    if args.resume is not None:
        return _resume_main(cfg, args, floor)
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
    known = list(cfg["models"]) + list(cfg["remote_models"])
    bad_models = [m for m in models if m not in known]
    if bad_models and not args.allow_any_model:
        return _fail(f"unknown model(s) {bad_models}; configured: "
                     f"{known} (use --allow-any-model to override)")
    n_runs = args.n_runs if args.n_runs is not None else cfg["n_runs"]
    if n_runs < 1:
        return _fail("--n-runs must be at least 1")
    try:
        temperatures = (list(cfg["temperatures"]) if args.temperatures is None
                        else _parse_temperatures(args.temperatures))
    except ValueError as exc:
        return _fail(str(exc))
    defense_ids = [NO_DEFENSE["id"]] if args.defenses is None else _csv(args.defenses)
    try:
        resolve_defenses(cfg, defense_ids)
    except ValueError as exc:
        return _fail(f"--defenses: {exc}")
    telemetry = cfg["telemetry_enabled"] if args.telemetry is None else args.telemetry
    problem = hosted_problem(models, telemetry, os.environ)
    if problem:
        return _fail(problem)
    batch_id = args.batch_id or _utc_stamp()
    given = list(sys.argv[1:] if argv is None else argv)
    command = ["run_eval.py", *(a for a in given if a != "--plan")]
    if args.plan:
        try:
            check_new_batch_id(cfg["results_dir"], batch_id)
        except ValueError as exc:
            return _fail(str(exc))
        print(json.dumps(_plan(batch_id, models, scenario_ids, temperatures, n_runs,
                               telemetry, command, defense_ids)))
        return 0
    low = memory_problem(models, floor, free_memory_bytes)
    if low:
        return _fail(f"{low}; the batch was not started. Close other programs, or pass "
                     "--stop-free-memory-gb 0 to run without the check")
    try:
        prep = prepare_batch(cfg, models, scenario_ids, n_runs, telemetry, batch_id,
                             temperatures=temperatures, config_path=args.config,
                             command=command, defense_ids=defense_ids,
                             free_memory_fn=free_memory_bytes, stop_free_memory_gb=floor,
                             digests=model_digests(cfg, models))
    except ValueError as exc:
        return _fail(str(exc))
    return _execute_main(prep)


def _resume_main(cfg: dict, args, floor: float) -> int:
    """--resume: the selection comes from batch.json, so selection flags are refused."""
    given = [f for f, v in (("--models", args.models), ("--scenarios", args.scenarios),
                            ("--n-runs", args.n_runs),
                            ("--temperatures", args.temperatures),
                            ("--defenses", args.defenses), ("--telemetry", args.telemetry),
                            ("--batch-id", args.batch_id)) if v is not None]
    if given or args.plan:
        return _fail("--resume takes the selection from the batch's own batch.json; "
                     f"remove {', '.join(given) or '--plan'}")
    try:
        prep = prepare_resume(
            cfg, args.resume, config_path=args.config, free_memory_fn=free_memory_bytes,
            stop_free_memory_gb=floor,
            digests_fn=lambda: model_digests(cfg, _plan_models(cfg, args.resume)))
    except ValueError as exc:
        return _fail(str(exc))
    problem = hosted_problem(prep.models, prep.telemetry, os.environ)
    if problem:
        return _fail(problem)
    low = memory_problem(prep.models, floor, free_memory_bytes)
    if low:
        return _fail(f"{low}; the batch was not resumed")
    print(f"resuming batch {args.resume}: {prep.resumed[-1]['recorded_before']} run(s) "
          f"recorded, {prep.resumed[-1]['remaining']} to go")
    return _execute_main(prep)


def _plan_models(cfg: dict, batch_id: str) -> list[str]:
    plan = batch_plan.read_plan(os.path.join(cfg["results_dir"], batch_id)) or {}
    return list(plan.get("models") or [])


def _execute_main(prep: PreparedBatch) -> int:
    batch_id = prep.batch_log.batch_id
    try:
        out = execute_batch(prep)
    except ListenerStartError as exc:
        return _fail(str(exc))
    except Exception as exc:  # a late failure: reported with its traceback, exit 1
        log.exception("batch %s failed", batch_id)
        return _fail(f"batch {batch_id} failed ({type(exc).__name__}: {exc}); "
                     f"output folder: {prep.batch_log.out_dir}")
    _print_results(out)
    if out["aborted"]:
        return _fail(f"batch {batch_id} aborted: {out['abort_reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
