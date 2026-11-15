"""batch.json: what a batch was asked to run and how it ended (CLAUDE.md 4.8).

Written by run_eval when a batch opens; read by the dashboard and the regrade command.
No key is ever written here.
"""
import json
import os

PLAN_FILE = "batch.json"
FIELDS = ("batch_id", "models", "scenario_ids", "temperatures", "n_runs",
          "telemetry_enabled", "temps_per_model", "planned_runs", "command", "pid",
          "started_at", "ended_at", "aborted", "abort_reason")


def build_plan(batch_id: str, models: list, scenario_ids: list, temperatures: list,
               n_runs: int, telemetry: bool, temps_per_model: dict,
               command: list | None) -> dict:
    planned = sum(len(temps_per_model[m]) for m in models) * len(scenario_ids) * n_runs
    return {"batch_id": batch_id, "models": list(models),
            "scenario_ids": list(scenario_ids), "temperatures": list(temperatures),
            "n_runs": n_runs, "telemetry_enabled": telemetry,
            "temps_per_model": {m: list(t) for m, t in temps_per_model.items()},
            "planned_runs": planned, "command": None if command is None else list(command),
            "pid": None, "started_at": None, "ended_at": None, "aborted": None,
            "abort_reason": None}


def write_plan(out_dir: str, plan: dict) -> str:
    """Write the plan through a temp file, so a reader never sees half a file."""
    path = os.path.join(out_dir, PLAN_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(plan, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    os.replace(tmp, path)
    return path


def read_plan(out_dir: str) -> dict | None:
    """The plan, or None when the batch has no batch.json (batches before 4.8)."""
    path = os.path.join(out_dir, PLAN_FILE)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        plan = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"{path} (batch.json) is not valid JSON: {exc}") from exc
    if not isinstance(plan, dict):
        raise ValueError(f"{path} (batch.json) is not a JSON object")
    return plan


def update_plan(out_dir: str, **fields) -> dict:
    unknown = [k for k in fields if k not in FIELDS]
    if unknown:
        raise KeyError(f"unknown batch.json field(s) {unknown}")
    plan = read_plan(out_dir)
    if plan is None:
        raise ValueError(f"no {PLAN_FILE} in {out_dir}")
    plan.update(fields)
    write_plan(out_dir, plan)
    return plan


def finalise_plan(out_dir: str, ended_at: str, aborted: bool,
                  abort_reason: str | None) -> None:
    update_plan(out_dir, ended_at=ended_at, aborted=aborted, abort_reason=abort_reason)
