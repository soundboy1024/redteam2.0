"""batch.json: what a batch was asked to run and how it ended (CLAUDE.md 4.8).

Written by run_eval when a batch opens; read by the dashboard and the regrade command.
No key is ever written here.
"""
import ctypes
import json
import os
import sys
import time

PLAN_FILE = "batch.json"
REPLACE_ATTEMPTS = 10
REPLACE_WAIT_S = 0.2
_QUERY_LIMITED = 0x1000   # PROCESS_QUERY_LIMITED_INFORMATION
_STILL_ACTIVE = 259
FIELDS = ("batch_id", "models", "scenario_ids", "temperatures", "n_runs",
          "telemetry_enabled", "temps_per_model", "planned_runs", "command", "pid",
          "pid_create_time", "started_at", "ended_at", "aborted", "abort_reason",
          "defenses")


def build_plan(batch_id: str, models: list, scenario_ids: list, temperatures: list,
               n_runs: int, telemetry: bool, temps_per_model: dict,
               command: list | None, defenses: list | None = None) -> dict:
    """defenses is a list of defense ids (CLAUDE.md 4.10); None means ["none"]."""
    defenses = ["none"] if defenses is None else list(defenses)
    if not defenses:
        raise ValueError("a batch needs at least one defense id ('none' for bare)")
    planned = (sum(len(temps_per_model[m]) for m in models) * len(scenario_ids)
               * len(defenses) * n_runs)
    return {"batch_id": batch_id, "models": list(models),
            "scenario_ids": list(scenario_ids), "temperatures": list(temperatures),
            "n_runs": n_runs, "telemetry_enabled": telemetry,
            "temps_per_model": {m: list(t) for m, t in temps_per_model.items()},
            "planned_runs": planned, "command": None if command is None else list(command),
            "pid": None, "pid_create_time": None, "started_at": None, "ended_at": None,
            "aborted": None, "abort_reason": None, "defenses": defenses}


def write_plan(out_dir: str, plan: dict) -> str:
    """Write the plan through a temp file, so a reader never sees half a file."""
    path = os.path.join(out_dir, PLAN_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(plan, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    try:
        for attempt in range(REPLACE_ATTEMPTS):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                # Windows: a reader (the dashboard) has the file open this instant
                if attempt == REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(REPLACE_WAIT_S)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path


def process_create_time(pid) -> int | None:
    """The creation time of a live process as an opaque integer, or None when there is
    no live process with that pid (or this is not Windows). A pid alone can be reused by
    another process; pid plus creation time identifies one process."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    kernel32.GetProcessTimes.argtypes = (ctypes.c_void_p,) + (ctypes.c_void_p,) * 4
    kernel32.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    handle = kernel32.OpenProcess(_QUERY_LIMITED, 0, pid)
    if not handle:
        return None
    try:
        code = ctypes.c_uint32()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return None
        if code.value != _STILL_ACTIVE:
            return None
        times = [ctypes.c_uint64() for _ in range(4)]
        if not kernel32.GetProcessTimes(handle, *(ctypes.byref(x) for x in times)):
            return None
        return int(times[0].value)
    finally:
        kernel32.CloseHandle(handle)


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
