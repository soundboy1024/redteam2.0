"""Per-run runner: one scenario, one model, one repetition. Must not import from
traps/ or telemetry/; scenarios.json is read as a plain data file.
"""
import json
import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from harness.agent_loop import run_agent
from harness.ollama_client import ChatResult, OllamaError
from harness.tools import ListenerUnreachable, ToolContext

log = logging.getLogger(__name__)

# Caught and recorded as an invalid run; everything else propagates.
INFRA_ERRORS = (ListenerUnreachable, OllamaError, ValueError)

# Hard-coded (no telemetry import); tests/test_runner.py checks it against RUN_COLUMNS.
RUN_KEYS = ("run_id", "batch_id", "model_name", "scenario_id", "attack_taxonomy",
            "repetition_index", "temperature", "telemetry_enabled", "started_at",
            "ended_at", "status", "invalid_reason", "stop_reason",
            "final_response", "steps", "parse_failures", "poison_ingested",
            "ctx_tripwire_canary_read", "ctx_tripwire_unauth_tool_call")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_scenarios(scenarios_path: str) -> list[dict]:
    with open(scenarios_path, encoding="utf-8") as f:
        scenarios = json.load(f)
    if not isinstance(scenarios, list):
        raise ValueError(f"{scenarios_path}: top level must be a list")
    return scenarios


def _remove_workspace(tmp_root: str) -> None:
    try:
        shutil.rmtree(tmp_root)
    except OSError:
        # Logged, never raised: must not mask an exception already in flight.
        log.error("could not remove temp workspace %s", tmp_root, exc_info=True)


def _record(**values) -> dict:
    if set(values) != set(RUN_KEYS):
        raise RuntimeError(f"harness bug: run record keys {sorted(values)} != RUN_KEYS")
    return values


def _check_counts(rows: list[dict], outcome) -> tuple[int, int, bool]:
    steps = sum(1 for r in rows if r["step_index"] >= 1)
    parse_failures = sum(1 for r in rows if r["tool_call_parse_failed"])
    poison = any(r["poison_ingested"] for r in rows)
    if (steps, parse_failures, poison) != (
            outcome.steps, outcome.parse_failures, outcome.poison_ingested):
        raise RuntimeError(
            "harness bug: emitted step rows disagree with the agent outcome: "
            f"rows=({steps}, {parse_failures}, {poison}) outcome=({outcome.steps}, "
            f"{outcome.parse_failures}, {outcome.poison_ingested})")
    return steps, parse_failures, poison


def run_one(scenario: dict, fixtures_root: str, model: str, repetition_index: int,
            cfg: dict, *, batch_id: str, telemetry: bool,
            chat_fn: Callable[[list[dict]], ChatResult],
            step_sink: Callable[[dict], None],
            event_sink: Callable[[str, dict], None]) -> dict:
    run_id = str(uuid.uuid4())
    started_at = _now()
    host, port = cfg["listener"]["host"], cfg["listener"]["port"]
    emitted: list[dict] = []

    def sink(row: dict) -> None:
        row = {"run_id": run_id, "timestamp": _now(), "model_name": model,
               "scenario_id": scenario["id"],
               "attack_taxonomy": scenario["attack_taxonomy"],
               "repetition_index": repetition_index,
               "temperature": cfg["temperature"], **row}
        emitted.append(row)
        step_sink(row)

    tmp_root = tempfile.mkdtemp(prefix="rt_ws_")
    try:
        workspace = Path(tmp_root) / "workspace"
        shutil.copytree(os.path.join(fixtures_root, scenario["fixture_dir"]), workspace)
        ctx = ToolContext(
            run_id=run_id, workspace=workspace,
            canary_files=list(scenario["canary_files"]),
            allowed_endpoints=list(scenario["allowed_endpoints"]),
            event_sink=lambda event: event_sink(run_id, event),
            base_url=f"http://{host}:{port}")
        status, invalid_reason, stop_reason, final = "completed", None, None, None
        outcome = None
        try:
            outcome = run_agent(chat_fn, ctx, scenario["user_prompt"],
                                list(scenario["poison_files"]), cfg["max_steps"], sink)
        except INFRA_ERRORS as exc:
            log.error("run %s (%s, %s, rep %s) invalid: %s: %s", run_id, scenario["id"],
                      model, repetition_index, type(exc).__name__, exc)
            status = "invalid"
            invalid_reason = f"{type(exc).__name__}: {exc}"
            stop_reason = "error"
        if outcome is not None:
            steps, parse_failures, poison = _check_counts(emitted, outcome)
            stop_reason, final = outcome.stop_reason, outcome.final_response
        else:
            steps = sum(1 for r in emitted if r["step_index"] >= 1)
            parse_failures = sum(1 for r in emitted if r["tool_call_parse_failed"])
            poison = any(r["poison_ingested"] for r in emitted)
        return _record(
            run_id=run_id, batch_id=batch_id, model_name=model,
            scenario_id=scenario["id"], attack_taxonomy=scenario["attack_taxonomy"],
            repetition_index=repetition_index, temperature=cfg["temperature"],
            telemetry_enabled=bool(telemetry), started_at=started_at, ended_at=_now(),
            status=status, invalid_reason=invalid_reason, stop_reason=stop_reason,
            final_response=final, steps=steps, parse_failures=parse_failures,
            poison_ingested=poison,
            ctx_tripwire_canary_read=ctx.tripwire_canary_read,
            ctx_tripwire_unauth_tool_call=ctx.tripwire_unauth_tool_call)
    finally:
        _remove_workspace(tmp_root)
