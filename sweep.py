"""Model sweep (CLAUDE.md 4.9): for each model in a queue, pull it, check it loads, run the
scenarios through run_eval.py, confirm the results, delete it, and record what happened.

Usage: .venv\\Scripts\\python.exe sweep.py --sweep-id <name> [--queue sweep_queue.yaml]
                                          [--config config.yaml] [--dry-run]

A batch is only ever the run_eval.py command, run as a separate process. This file imports
nothing from harness/, traps/ or telemetry/. A model that was installed before the sweep
is never deleted. Start it again with the same --sweep-id to continue: finished models are
skipped and unfinished ones are tried again.
"""
import argparse
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Callable

import batch_plan
import sweep_probe
import sweep_record
from sweep_probe import ProbeError

log = logging.getLogger("sweep")
GB = 2 ** 30
FAILURES_IN_A_ROW = 3
PLAN_WAIT_S = 60
MAX_BATCH_ID = 64      # telemetry/logger.py BATCH_ID_RE
SWEEP_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")


class Preflight(RuntimeError):
    """A condition that stops the whole sweep, not just one model."""


@dataclass
class Settings:
    sweep_id: str
    root: str
    python_exe: str
    config_path: str
    results_dir: str
    num_ctx: int
    temperatures: list
    min_free_disk: int        # bytes
    min_free_memory: int      # bytes
    stop_free_memory: int     # bytes
    watch_s: float = 30


@dataclass
class Deps:
    """Everything the sweep does to the outside world, so tests can replace it."""
    installed: Callable[[], dict]
    loaded: Callable[[], list]
    pull: Callable[[str], None]
    load_check: Callable[[str], dict]
    unload: Callable[[str], bool]
    delete: Callable[[str], None]
    free_memory: Callable[[], int]
    free_disk: Callable[[], int]
    log_size: Callable[[], int]
    backend: Callable[[int], str | None]
    start_batch: Callable[[list, str], object]
    stop_batch: Callable[[dict], dict]
    read_plan: Callable[[str], dict | None]
    port_open: Callable[[], bool]
    sleep: Callable[[float], None]


def _gb(value: int) -> str:
    return f"{value / GB:.1f} GB"


def batch_id(sweep_id: str, tag: str, temperature, attempt: int) -> str:
    base = (f"sweep-{sweep_id}-{sweep_record.slug(tag)}-"
            f"t{str(temperature).replace('.', '')}")
    return base if attempt <= 1 else f"{base}-r{attempt}"


def preflight(s: Settings, d: Deps) -> None:
    if d.port_open():
        raise Preflight("the listener port is in use: a batch or a gate is running")
    try:
        loaded = d.loaded()
    except ProbeError as exc:
        raise Preflight(f"Ollama cannot be reached: {exc}") from exc
    if loaded:
        raise Preflight("Ollama still has a model loaded: "
                        + ", ".join(m["name"] for m in loaded))
    disk = d.free_disk()
    if disk < s.min_free_disk:
        raise Preflight(f"free disk is {_gb(disk)}, under the floor of "
                        f"{_gb(s.min_free_disk)}")
    memory = d.free_memory()
    if memory < s.min_free_memory:
        raise Preflight(f"free memory is {_gb(memory)}, under the floor of "
                        f"{_gb(s.min_free_memory)}")


def verify_batch(s: Settings, d: Deps, bid: str, exit_code) -> tuple[bool, str | None, int | None, int | None]:
    """(ok, reason, valid, invalid) for a batch that has ended."""
    out_dir = os.path.join(s.results_dir, bid)
    valid = invalid = None
    rows = None
    path = os.path.join(out_dir, "results.json")
    problems = []
    if exit_code != 0:
        problems.append(f"run_eval.py ended with exit code {exit_code}")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                rows = json.load(f)["results"]
            valid = sum(1 for r in rows if r.get("valid") is not False)
            invalid = len(rows) - valid
            if rows and valid == 0:
                problems.append("no valid run was recorded (every run was invalid)")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            problems.append(f"results.json could not be read: {type(exc).__name__}: {exc}")
            rows = None
    else:
        problems.append("results.json was not written")
    try:
        plan = d.read_plan(out_dir)
    except ValueError as exc:
        plan = None
        problems.append(str(exc))
    if plan is None:
        problems.append("batch.json is missing")
    else:
        if plan.get("aborted") is not False or not plan.get("ended_at"):
            problems.append("the batch is marked aborted or never recorded its end"
                            + (f" ({plan['abort_reason']})" if plan.get("abort_reason") else ""))
        planned = plan.get("planned_runs")
        if rows is not None and len(rows) != planned:
            problems.append(f"{len(rows)} of {planned} planned runs were recorded")
    return (not problems, "; ".join(problems) or None, valid, invalid)


def _stop(s: Settings, d: Deps, bid: str, proc) -> str | None:
    """Stop a running batch through the pid in its own batch.json. Returns a problem, or
    None when it was stopped (or had already ended)."""
    out_dir = os.path.join(s.results_dir, bid)
    plan, waited = None, 0
    while proc.poll() is None:
        try:
            plan = d.read_plan(out_dir)
        except ValueError as exc:
            log.warning("batch %s: %s", bid, exc)
        if (plan is not None and isinstance(plan.get("pid"), int)) or waited >= PLAN_WAIT_S:
            break
        d.sleep(2)
        waited += 2
    if proc.poll() is not None:
        return None
    if plan is None or not isinstance(plan.get("pid"), int):
        log.error("batch %s has not recorded its process in batch.json after %s s, so it "
                  "cannot be stopped safely; its process is left running", bid, PLAN_WAIT_S)
        return ("the batch could not be stopped: it had not recorded its process in "
                "batch.json")
    try:
        out = d.stop_batch(plan)
    except ValueError as exc:      # the process ended, or cannot be identified
        log.warning("batch %s was not stopped: %s", bid, exc)
        return None if proc.poll() is not None else f"the batch could not be stopped: {exc}"
    log.warning("batch %s stopped: %s", bid, {k: out[k] for k in out if k != "regrade_output"})
    if not out.get("killed") and proc.poll() is None:
        return "the batch could not be stopped: " + str(out.get("regrade_output"))[-300:]
    if out.get("regrade_exit") != 0:
        log.error("batch %s was stopped but could not be regraded: %s", bid,
                  str(out.get("regrade_output"))[-300:])
    return None


def _run_batch(tag: str, temperature, bid: str, s: Settings, d: Deps) -> tuple[dict, str | None]:
    """Run one batch and watch memory. Returns (batch entry, stop kind): stop kind is
    None, "memory" or "interrupt"."""
    command = [s.python_exe, "run_eval.py", "--config", s.config_path, "--models", tag,
               "--allow-any-model", "--temperatures", str(temperature), "--batch-id", bid,
               # the sweep watches memory itself and records the stop (4.9 step 7)
               "--stop-free-memory-gb", "0"]
    console = os.path.join(s.results_dir, "_console", bid + ".log")
    entry = {"batch_id": bid, "temperature": temperature, "exit_code": None, "ok": False,
             "reason": None, "valid": None, "invalid": None,
             "free_memory_start": _free(d), "free_memory_end": None,
             "lowest_free_memory": None, "left_running": False}
    lowest = entry["free_memory_start"]
    log.info("%s: starting batch %s: %s", tag, bid, " ".join(command))
    try:
        proc = d.start_batch(command, console)
    except (OSError, RuntimeError) as exc:
        entry["reason"] = f"the batch could not be started: {type(exc).__name__}: {exc}"
        entry["lowest_free_memory"] = lowest
        log.error("%s: batch %s: %s", tag, bid, entry["reason"])
        return entry, None
    stop_kind = stop_reason = None
    try:
        while proc.poll() is None:
            d.sleep(s.watch_s)
            free = d.free_memory()
            lowest = free if lowest is None else min(lowest, free)
            if free < s.stop_free_memory and proc.poll() is None:
                stop_kind = "memory"
                stop_reason = (f"stopped for memory: free memory fell to {_gb(free)}, under "
                               f"the stop floor of {_gb(s.stop_free_memory)}")
                log.error("%s: batch %s %s", tag, bid, stop_reason)
                break
    except KeyboardInterrupt:
        stop_kind, stop_reason = "interrupt", "interrupted (Ctrl+C) during the batch"
        log.error("%s: batch %s %s", tag, bid, stop_reason)
    except ProbeError as exc:
        stop_kind = "error"
        stop_reason = f"stopped because free memory could not be read: {exc}"
        log.error("%s: batch %s %s", tag, bid, stop_reason)
    if stop_kind:
        problem = _stop(s, d, bid, proc)
        if problem:
            stop_reason += "; " + problem
            entry["left_running"] = proc.poll() is None
    exit_code = proc.poll()
    entry["exit_code"] = exit_code
    entry["free_memory_end"] = _free(d)
    known = [v for v in (lowest, entry["free_memory_end"]) if v is not None]
    entry["lowest_free_memory"] = min(known) if known else None
    if entry["left_running"]:
        entry["reason"] = stop_reason
        return entry, stop_kind
    ok, reason, valid, invalid = verify_batch(s, d, bid, exit_code)
    entry["valid"], entry["invalid"] = valid, invalid
    if stop_kind:
        entry["ok"], entry["reason"] = False, stop_reason
    else:
        entry["ok"], entry["reason"] = ok, reason
    log.info("%s: batch %s ended: ok=%s valid=%s invalid=%s reason=%s", tag, bid,
             entry["ok"], valid, invalid, entry["reason"])
    return entry, stop_kind


def _free(d: Deps) -> int | None:
    """Free memory for the record; None (logged) when it cannot be read."""
    try:
        return d.free_memory()
    except ProbeError as exc:
        log.error("free memory could not be read: %s", exc)
        return None


def _resolve(tag: str, names) -> str | None:
    """The installed name this tag refers to, by the same rule as is_installed."""
    for name in (tag, tag + ":latest", tag[:-len(":latest")] if tag.endswith(":latest") else tag):
        if name in names:
            return name
    return None


def batch_id_problem(sweep_id: str, tags: list, temperatures: list) -> str | None:
    """Why the batch ids of this sweep would be refused by run_eval.py, or None."""
    for tag in tags:
        longest = max(len(batch_id(sweep_id, tag, t, 99)) for t in temperatures)
        if longest > MAX_BATCH_ID:
            return (f"batch ids for {tag} would be {longest} characters, over the limit of "
                    f"{MAX_BATCH_ID}; use a shorter --sweep-id")
    return None


def _add_reason(rec: dict, text: str) -> None:
    rec["reason"] = text if not rec["reason"] else f"{rec['reason']}; {text}"


def _lookup(tag: str, names: dict) -> dict:
    for name in (tag, tag + ":latest", tag[:-len(":latest")] if tag.endswith(":latest") else tag):
        if name in names:
            return names[name]
    return {}


def run_model(tag: str, s: Settings, d: Deps, attempt: int = 1, prior: dict | None = None,
              save: Callable[[dict], None] | None = None) -> dict:
    """Every step for one model. Always returns its record; never raises for anything the
    model, Ollama or a Ctrl+C does."""
    save = save or (lambda record: None)
    rec = sweep_record.new_record(tag)
    rec["attempt"] = attempt
    started = time.monotonic()
    loaded_by_us = False

    def fail(status: str, reason: str) -> None:
        rec["status"] = status
        _add_reason(rec, reason)
        log.error("%s: %s: %s", tag, status, reason)

    try:
        try:
            names = d.installed()
        except ProbeError as exc:
            fail("pull_failed", f"could not list installed models: {exc}")
            names = None
        if names is not None:
            present = sweep_probe.is_installed(tag, names)
            # an earlier attempt's pull counts only while the installed model is still
            # the same one (same digest)
            claimed = bool(present and prior and prior.get("pulled_by_sweep") is True
                           and prior.get("deleted") is not True and prior.get("digest")
                           and _lookup(tag, names).get("digest") == prior["digest"])
            if present:
                rec["pulled_by_sweep"] = claimed
                log.info("%s: already installed (%s)", tag,
                         "left by an earlier attempt of this sweep" if claimed
                         else "not the sweep's, will not be deleted")
            save(rec)
            if not present:
                log.info("%s: pulling", tag)
                try:
                    d.pull(tag)
                    new_name = _resolve(tag, d.installed())
                    if new_name is None or new_name in names:
                        # the pull changed nothing under this name: the tag is another
                        # spelling of something else, so nothing here is the sweep's
                        rec["pulled_by_sweep"] = False
                        fail("pull_failed", "the pull reported success but added no new "
                             f"model named {tag} to the installed list; nothing is claimed "
                             "or deleted")
                    else:
                        rec["pulled_by_sweep"] = True
                        save(rec)
                except ProbeError as exc:
                    rec["pulled_by_sweep"] = False
                    fail("pull_failed", str(exc))
        if rec["status"] is None:
            try:
                info = _lookup(tag, d.installed())
                rec["digest"], rec["download_size"] = info.get("digest"), info.get("size")
                offset = d.log_size()
                loaded_by_us = True
                rec["tokens_per_s"] = d.load_check(tag)["tokens_per_s"]
                entry = _lookup(tag, {m["name"]: m for m in d.loaded()})
                size, vram = entry.get("size"), entry.get("size_vram")
                rec["size_in_memory"] = size
                rec["gpu_share"] = vram / size if size and vram is not None else None
                rec["free_memory_after_load"] = rec["lowest_free_memory"] = d.free_memory()
                rec["backend"] = d.backend(offset)
            except ProbeError as exc:
                fail("load_failed", str(exc))
        if rec["status"] is None and rec["free_memory_after_load"] < s.min_free_memory:
            fail("does_not_fit", f"free memory after loading was "
                 f"{_gb(rec['free_memory_after_load'])}, under the floor of "
                 f"{_gb(s.min_free_memory)}")
        if rec["status"] is None:
            for temperature in s.temperatures:
                entry, stop_kind = _run_batch(
                    tag, temperature, batch_id(s.sweep_id, tag, temperature, attempt), s, d)
                rec["batches"].append(entry)
                if entry["lowest_free_memory"] is not None:
                    rec["lowest_free_memory"] = min(rec["lowest_free_memory"],
                                                    entry["lowest_free_memory"])
                if entry["left_running"]:
                    rec["batch_left_running"] = True
                else:
                    loaded_by_us = not _unload(tag, d, rec)
                if stop_kind == "memory":
                    fail("stopped_for_memory", entry["reason"])
                elif stop_kind == "interrupt":
                    fail("stopped", entry["reason"])
                elif stop_kind == "error":
                    fail("batch_failed", f"batch {entry['batch_id']}: {entry['reason']}")
                elif not entry["ok"]:
                    fail("batch_failed", f"batch {entry['batch_id']}: {entry['reason']}")
                elif loaded_by_us:
                    fail("batch_failed", "the model did not unload after a batch, so the "
                         "remaining batches were not run")
                if rec["status"] is not None:
                    break
            else:
                rec["status"] = "completed"
    except KeyboardInterrupt:
        fail("stopped", "interrupted (Ctrl+C)")
        if rec["pulled_by_sweep"] is None:
            rec["pulled_by_sweep"] = False
    except (ProbeError, OSError) as exc:
        fail("batch_failed", f"unexpected failure: {type(exc).__name__}: {exc}")
    _finish(tag, rec, d, loaded_by_us, save)
    rec["seconds"] = round(time.monotonic() - started, 1)
    return rec


def _unload(tag: str, d: Deps, rec: dict) -> bool:
    try:
        if d.unload(tag):
            return True
        problem = "the model did not unload"
    except ProbeError as exc:
        problem = f"the model did not unload: {exc}"
    log.error("%s: %s", tag, problem)
    _add_reason(rec, problem)
    return False


def _finish(tag: str, rec: dict, d: Deps, loaded_by_us: bool, save) -> None:
    """Unload, write the record, then delete the model if the sweep pulled it."""
    rec["deleted"] = False
    if rec["batch_left_running"]:
        _add_reason(rec, "the model was left installed and loaded because its batch may "
                    "still be running")
        log.error("%s: left installed and loaded: its batch may still be running", tag)
        save(rec)
        return
    try:
        unloaded = _unload(tag, d, rec) if loaded_by_us else True
        if not unloaded and rec["status"] == "completed":
            rec["status"] = "batch_failed"
        save(rec)
        if rec["pulled_by_sweep"] is True and unloaded:
            try:
                d.delete(tag)
                rec["deleted"] = True
                log.info("%s: deleted", tag)
            except ProbeError as exc:
                log.error("%s: delete failed: %s", tag, exc)
                _add_reason(rec, f"delete failed: {exc}")
                if rec["status"] == "completed":
                    rec["status"] = "batch_failed"
        if rec["status"] != "pull_failed":
            try:
                rec["installed_after"] = sweep_probe.is_installed(tag, d.installed())
            except ProbeError as exc:
                log.error("%s: could not list installed models after the run: %s", tag, exc)
                _add_reason(rec, f"could not confirm the installed list: {exc}")
    except KeyboardInterrupt:
        log.error("%s: interrupted during clean-up; the model may still be installed", tag)
        _add_reason(rec, "interrupted (Ctrl+C) during clean-up")
        rec["status"] = "stopped"


def run_sweep(queue: dict, s: Settings, d: Deps) -> int:
    sdir = sweep_record.sweep_dir(s.results_dir, s.sweep_id)
    records = sweep_record.read_records(sdir)
    failures = 0

    def write(stopped_reason: str | None = None) -> None:
        sweep_record.write_records(sdir, s.sweep_id, records, stopped_reason)

    def save(record: dict) -> None:
        nonlocal records
        records = sweep_record.upsert(records, record)
        write()

    for tag in queue["models"]:
        if sweep_record.is_done(sdir, tag):
            log.info("%s: done in an earlier run of this sweep, skipped", tag)
            continue
        try:
            preflight(s, d)
        except Preflight as exc:
            log.error("sweep stopped before %s: %s", tag, exc)
            write(f"stopped before {tag}: {exc}")
            return 2
        prior = next((r for r in records if r["tag"] == tag), None)
        attempt = (prior.get("attempt") or 1) + 1 if prior else 1
        log.info("%s: starting (attempt %s)", tag, attempt)
        record = run_model(tag, s, d, attempt, prior, save)
        save(record)
        log.info("%s: %s%s", tag, record["status"],
                 f" ({record['reason']})" if record["reason"] else "")
        if record["status"] == "completed":
            sweep_record.mark_done(sdir, tag)
        if record["batch_left_running"]:
            reason = (f"a batch of {tag} could not be stopped and may still be running; "
                      "stop it where it shows (the Run page or its console) before "
                      "starting the sweep again")
            log.error("sweep stopped: %s", reason)
            write(reason)
            return 4
        if record["status"] == "stopped":
            write(f"interrupted during {tag}")
            return 130
        failures = failures + 1 if record["status"] in ("pull_failed", "load_failed") else 0
        if failures >= FAILURES_IN_A_ROW:
            reason = (f"{FAILURES_IN_A_ROW} models in a row failed to pull or load (last: "
                      f"{tag}); check Ollama and the network")
            log.error("sweep stopped: %s", reason)
            write(reason)
            return 3
    write()
    return 0


def dry_run(queue: dict, s: Settings, d: Deps) -> None:
    sdir = sweep_record.sweep_dir(s.results_dir, s.sweep_id)
    try:
        names = d.installed()
    except ProbeError as exc:
        log.warning("Ollama cannot be reached, installed state unknown: %s", exc)
        names = None
    for tag in queue["models"]:
        if sweep_record.is_done(sdir, tag):
            state = "done, would be skipped"
        elif names is None:
            state = "to do; installed state unknown"
        elif sweep_probe.is_installed(tag, names):
            state = "to do; already installed, would not be deleted"
        else:
            state = "to do; to pull, then delete"
        print(f"{tag}: {state}")


def real_deps(cfg: dict, s: Settings) -> Deps:
    from dashboard import control   # start and stop a batch exactly as the Run page does
    host = cfg["ollama_host"]
    l_host, l_port = cfg["listener"]["host"], cfg["listener"]["port"]
    models_dir = os.environ.get("OLLAMA_MODELS") or os.path.expanduser("~")
    return Deps(
        installed=lambda: sweep_probe.installed(host),
        loaded=lambda: sweep_probe.loaded(host),
        pull=lambda tag: sweep_probe.pull(host, tag),
        load_check=lambda tag: sweep_probe.load_check(host, tag, s.num_ctx),
        unload=lambda tag: sweep_probe.unload(host, tag),
        delete=lambda tag: sweep_probe.delete(host, tag),
        free_memory=sweep_probe.free_memory_bytes,
        free_disk=lambda: sweep_probe.free_disk_bytes(models_dir),
        log_size=lambda: sweep_probe.log_size(sweep_probe.DEFAULT_LOG),
        backend=lambda offset: sweep_probe.backend_from_log(sweep_probe.DEFAULT_LOG, offset),
        start_batch=lambda command, console: control.start_batch(command, s.root, console,
                                                                 False, None),
        stop_batch=lambda plan: control.stop_batch(plan, s.root, s.python_exe, l_host, l_port,
                                                   s.config_path),
        read_plan=batch_plan.read_plan,
        port_open=lambda: control.port_open(l_host, l_port),
        sleep=time.sleep)


def _fail(message: str) -> int:
    print(f"sweep: {message}", file=sys.stderr)
    return 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Model sweep (CLAUDE.md 4.9).")
    p.add_argument("--sweep-id", required=True,
                   help="name of this sweep: lower-case letters, digits and hyphens")
    p.add_argument("--queue", default="sweep_queue.yaml")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--dry-run", action="store_true",
                   help="print what would happen to each model; change nothing")
    args = p.parse_args(argv)
    if not SWEEP_ID_RE.fullmatch(args.sweep_id):
        return _fail(f"--sweep-id {args.sweep_id!r} may only use lower-case letters, digits "
                     "and hyphens, and must start with a letter or digit")
    from rt_config import ConfigError, load_config
    try:
        cfg = load_config(args.config)
        queue = sweep_record.load_queue(args.queue)
    except (ConfigError, sweep_record.QueueError) as exc:
        return _fail(str(exc))
    root = os.path.dirname(os.path.abspath(__file__))
    problem = batch_id_problem(args.sweep_id, queue["models"], cfg["temperatures"])
    if problem:
        return _fail(problem)
    # run_eval.py runs with the repo root as its working directory, so every path the
    # sweep shares with it is made absolute here
    results_dir = cfg["results_dir"]
    if not os.path.isabs(results_dir):
        results_dir = os.path.join(root, results_dir)
    s = Settings(sweep_id=args.sweep_id, root=root, python_exe=sys.executable,
                 config_path=os.path.abspath(args.config), results_dir=results_dir,
                 num_ctx=cfg["num_ctx"], temperatures=list(cfg["temperatures"]),
                 min_free_disk=int(queue["min_free_disk_gb"] * GB),
                 min_free_memory=int(queue["min_free_memory_gb"] * GB),
                 stop_free_memory=int(queue["stop_free_memory_gb"] * GB))
    handlers = [logging.StreamHandler()]
    if not args.dry_run:
        sdir = sweep_record.sweep_dir(s.results_dir, s.sweep_id)
        os.makedirs(sdir, exist_ok=True)
        handlers.append(logging.FileHandler(os.path.join(sdir, "sweep.log"), encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, handlers=handlers, force=True,
                        format="%(asctime)s %(levelname)s %(message)s")
    d = real_deps(cfg, s)
    if args.dry_run:
        dry_run(queue, s, d)
        return 0
    try:
        code = run_sweep(queue, s, d)
    except KeyboardInterrupt:
        log.error("sweep interrupted between models")
        return 130
    log.info("sweep %s ended with exit code %s; record: %s", s.sweep_id, code,
             os.path.join(sweep_record.sweep_dir(s.results_dir, s.sweep_id), "sweep.md"))
    return code


if __name__ == "__main__":
    sys.exit(main())
