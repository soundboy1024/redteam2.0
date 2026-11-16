"""Starting, stopping and previewing a batch from the dashboard (CLAUDE.md 4.8).

A batch is only ever the `run_eval.py` command, run as a separate process. Nothing
here imports harness/ and nothing here reads a key's value.
"""
import json
import logging
import os
import socket
import subprocess
import time

import batch_plan

log = logging.getLogger(__name__)

KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "groq": "GROQ_API_KEY",
           "cerebras": "CEREBRAS_API_KEY", "google": "GOOGLE_API_KEY"}
STATES = ("starting", "running", "finishing", "finished", "aborted",
          "stopped_without_results", "unknown")
LIVE_STATES = ("starting", "running", "finishing")
PLAN_TIMEOUT_S = 30
PORT_CLOSE_WAIT_S = 15


class StartRefused(RuntimeError):
    """A batch was not started; the message says why."""


def provider_of(model: str) -> str | None:
    head = model.split("/", 1)[0]
    return head if "/" in model and head in KEY_ENV else None


def key_status(models: list[str], environ) -> dict[str, bool]:
    """Per hosted model: is its key variable set. Never returns a value."""
    return {m: bool(environ.get(KEY_ENV[provider_of(m)])) for m in models
            if provider_of(m) is not None}


def _fmt(t: float) -> str:
    return f"{t:g}"


def build_command(python_exe: str, models: list[str], scenario_ids: list[str],
                  temperatures: list[float], n_runs: int, batch_id: str,
                  config_path: str = "config.yaml",
                  defenses: list[str] | None = None) -> list[str]:
    """The run_eval command. --defenses is added only when the selection is not the
    default (bare only), so an ordinary batch has the same command as before."""
    command = [python_exe, "run_eval.py", "--config", config_path,
               "--models", ",".join(models), "--scenarios", ",".join(scenario_ids),
               "--temperatures", ",".join(_fmt(t) for t in temperatures),
               "--n-runs", str(n_runs), "--batch-id", batch_id]
    if defenses is not None and list(defenses) != ["none"]:
        command += ["--defenses", ",".join(defenses)]
    return command


def preview_plan(command: list[str], cwd: str) -> tuple[dict | None, str | None]:
    """Ask run_eval what the command would run. (plan, None) or (None, why not)."""
    try:
        done = subprocess.run([*command, "--plan"], cwd=cwd, capture_output=True, text=True,
                              timeout=PLAN_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"could not run the plan check: {type(exc).__name__}: {exc}"
    if done.returncode != 0:
        lines = [ln for ln in done.stderr.splitlines() if ln.startswith("error:")]
        return None, (lines[-1] if lines else done.stderr.strip()[-500:] or
                      f"plan check exited {done.returncode}")
    try:
        plan = json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        return None, f"plan check printed no JSON: {exc}"
    return plan, None


def port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def process_alive(plan: dict | None) -> tuple[bool, bool]:
    """(alive, identity_verified) for the batch process a plan records.

    A pid alone can be reused by an unrelated process, so the plan also records the
    process creation time. Verified means the live process has both. A plan written
    before the creation time was recorded can be alive but is never verified."""
    if not plan:
        return False, False
    created = batch_plan.process_create_time(plan.get("pid"))
    if created is None:
        return False, False
    recorded = plan.get("pid_create_time")
    if recorded is None:
        return True, False
    return created == recorded, True


def batch_state(plan: dict | None, alive: bool, verified: bool, port_is_open: bool,
                has_results_files: bool) -> str:
    """One of STATES. A batch is live only while its own process is alive; a port held
    by something else never makes a dead batch look alive."""
    if plan is None:
        return "finished" if has_results_files else "unknown"
    if plan.get("ended_at"):
        if alive and verified:
            return "finishing"  # still writing its results
        if not has_results_files:
            return "stopped_without_results"
        return "aborted" if plan.get("aborted") else "finished"
    if not plan.get("pid"):
        return "starting"
    if alive and (verified or port_is_open):
        return "running"
    return "stopped_without_results"


def start_batch(command: list[str], cwd: str, console_log: str, port_is_open: bool,
                running_batch: str | None) -> subprocess.Popen:
    if running_batch:
        raise StartRefused(f"batch {running_batch} is still running; one batch at a time")
    if port_is_open:
        raise StartRefused("the listener port is already in use; another batch or gate "
                           "is running")
    os.makedirs(os.path.dirname(console_log), exist_ok=True)
    flags = (getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
             | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    with open(console_log, "ab") as out:
        proc = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, creationflags=flags)
    log.info("started batch process pid=%s: %s", proc.pid, " ".join(command))
    return proc


def stop_batch(plan: dict, cwd: str, python_exe: str, host: str, port: int,
               config_path: str = "config.yaml") -> dict:
    """Kill the batch process recorded in this plan (and its listener child), then
    regrade the batch so what it recorded gets results. Only that pid is touched."""
    pid = plan.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        raise ValueError(f"batch {plan.get('batch_id')!r} has no process id to stop")
    if plan.get("ended_at"):
        raise ValueError(f"batch {plan.get('batch_id')!r} already ended")
    alive, verified = process_alive(plan)
    if not alive:
        raise ValueError(f"the process of batch {plan.get('batch_id')!r} is no longer "
                         "running; nothing to stop (use Regrade)")
    if not verified:
        raise ValueError(f"batch {plan.get('batch_id')!r} did not record which process it "
                         "is, so it cannot be stopped safely from here; stop it where it "
                         "was started")
    kill = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True,
                          text=True)
    log.warning("stop batch %s: taskkill pid=%s exit=%s %s", plan.get("batch_id"), pid,
                kill.returncode, (kill.stdout + kill.stderr).strip())
    if kill.returncode != 0 and process_alive(plan)[0]:
        return {"killed": False, "port_closed": not port_open(host, port),
                "regrade_exit": None,
                "regrade_output": "the batch process could not be stopped, so it was not "
                                  "regraded: " + (kill.stdout + kill.stderr).strip()[-500:]}
    deadline = time.monotonic() + PORT_CLOSE_WAIT_S
    while port_open(host, port) and time.monotonic() < deadline:
        time.sleep(0.5)
    regrade = subprocess.run([python_exe, "run_eval.py", "--config", config_path,
                              "--regrade", plan["batch_id"]],
                             cwd=cwd, capture_output=True, text=True)
    return {"killed": kill.returncode == 0, "port_closed": not port_open(host, port),
            "regrade_exit": regrade.returncode,
            "regrade_output": (regrade.stdout + regrade.stderr)[-2000:]}


def regrade_batch(batch_id: str, cwd: str, python_exe: str,
                  config_path: str = "config.yaml") -> dict:
    done = subprocess.run([python_exe, "run_eval.py", "--config", config_path,
                           "--regrade", batch_id], cwd=cwd, capture_output=True, text=True)
    return {"regrade_exit": done.returncode,
            "regrade_output": (done.stdout + done.stderr)[-2000:]}
