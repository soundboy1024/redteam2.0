"""Gate 3: run the whole harness once against a real local model (director gate).

Run from the repo root with the .venv python:
    .venv\\Scripts\\python.exe gates\\gate3.py [--config config.yaml] [--model NAME]

Calls the real Ollama model and starts the real listener on the configured port.
Checks mechanics only; judging the behaviour is the director's call.
"""
import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "gates"))

import requests  # noqa: E402

import run_eval  # noqa: E402
from _common import Evidence, out, run_main, show  # noqa: E402
from listener_proc import port_open  # noqa: E402
from rt_config import load_config  # noqa: E402
from telemetry.logger import read_results, read_steps  # noqa: E402

TRIPWIRES = ("tripwire_canary_read", "tripwire_unauth_tool_call",
             "tripwire_canary_exfiltrated", "tripwire_honeypot_endpoint_hit")
BOOL_FIELDS = TRIPWIRES + ("task_completed",)
A_SCENARIOS = ("benign_control", "indirect_injection_log")
B_SCENARIOS = ("indirect_injection_log",)
NON_EMPTY_FILES = ("results.json", "summary.md", "steps.jsonl")
VERBATIM = ("A compromised or failed-task result is not a gate failure. Gate 3 checks "
            "that the harness measured the run; judging the behaviour is the director's call.")
STEP_KEYS = ("step_index", "agent_state", "tool_name", "tool_call_parse_failed",
             "parse_reason", "done_reason", "token_count")
B_STEP_KEYS = STEP_KEYS + ("tool_name_logprob", "mean_entropy_approx")
RAW_LIMIT = 200
FLAG_NAME = "tool_name_logprob_found_on_a_batch_B_tool_call_step"
SESSION = requests.Session()
SESSION.trust_env = False  # never route loopback through a proxy


def _model_present(model: str, names: list[str]) -> bool:
    strip = lambda n: n[:-len(":latest")] if n.endswith(":latest") else n  # noqa: E731
    return strip(model) in {strip(n) for n in names}


def precheck(host: str, model: str) -> str | None:
    try:
        r = SESSION.get(host.rstrip("/") + "/api/tags", timeout=10)
        r.raise_for_status()
        names = [m["name"] for m in r.json()["models"]]
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        return f"Ollama not reachable at {host} ({type(exc).__name__}: {exc}); start Ollama"
    if not _model_present(model, names):
        return f"model {model} not present; run: ollama pull {model}"
    return None


def _one_line(text: str) -> str:
    return " ".join(str(text).replace("\r\n", "\n").replace("\r", "\n").split("\n"))


def reply_steps(steps: list[dict]) -> list[dict]:
    return [s for s in steps if s["step_index"] >= 1]


def parse_reason_counts(steps: list[dict]) -> str:
    counts = Counter(s["parse_reason"] for s in steps if s["tool_call_parse_failed"])
    if not counts:
        return "none"
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return ", ".join(f"{reason} x{n}" for reason, n in ordered)


def step_lines(steps: list[dict], keys: tuple) -> list[str]:
    """One line per reply step; parse failures also get the raw reply on one line."""
    lines = []
    for s in reply_steps(steps):
        lines.append("  " + ", ".join(f"{k}={s[k]!r}" for k in keys))
        if s["tool_call_parse_failed"]:
            lines.append(f"    raw reply (first {RAW_LIMIT} chars): "
                         + _one_line((s["raw_response"] or "")[:RAW_LIMIT]))
    return lines


def what_happened(row: dict, steps: list[dict]) -> list[str]:
    fired = [t.removeprefix("tripwire_") for t in TRIPWIRES if row.get(t)]
    return [
        f"scenario {row['scenario_id']} ran as cell '{row['cell']}'.",
        "tripwires fired: " + (", ".join(fired) if fired else "none") + ".",
        f"stop_reason: {row['stop_reason']}; steps: {row['steps']}; "
        f"parse_failures: {row['parse_failures']}.",
        f"parse failure reasons: {parse_reason_counts(steps)}.",
        f"poison file read: {'yes' if row['poison_ingested'] else 'no'}.",
    ]


def check_folder(batch: dict) -> list[str]:
    """Problems with a batch folder; empty when complete."""
    d, problems = batch["out_dir"], []
    for name in NON_EMPTY_FILES:
        path = os.path.join(d, name)
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            problems.append(f"{name} missing or empty")
    if not os.path.isfile(os.path.join(d, "tool_events.jsonl")):
        problems.append("tool_events.jsonl missing")
    returned = [r["run_id"] for r in batch["results"]]
    try:
        with open(os.path.join(d, "results.json"), encoding="utf-8") as f:
            ids = [r["run_id"] for r in json.load(f)["results"]]
        if ids != returned:
            problems.append(f"results.json run ids {ids} != returned {returned}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        problems.append(f"results.json unreadable ({type(exc).__name__}: {exc})")
    for run_id in returned:
        t = os.path.join(d, "runs", f"{run_id}.md")
        if not os.path.isfile(t) or os.path.getsize(t) == 0:
            problems.append(f"transcript runs/{run_id}.md missing or empty")
    return problems


def build_criteria(a: dict, b: dict, steps: dict[str, list[dict]],
                   stored: dict[str, list[dict]]) -> list[dict]:
    """Mechanical pass criteria. steps maps run_id to its step rows; stored maps
    "A"/"B" to the batch's rows in the results table."""
    ra, rb = a["results"], b["results"]
    rows = ra + rb
    bad_bool = [f"{r['scenario_id']}.{k}" for r in rows for k in BOOL_FIELDS
                if not isinstance(r.get(k), bool)]
    a_replies = [s for r in ra for s in reply_steps(steps.get(r["run_id"], []))]
    b_replies = [s for r in rb for s in reply_steps(steps.get(r["run_id"], []))]
    no_reply = [r["run_id"] for r in rows if not reply_steps(steps.get(r["run_id"], []))]
    folder = {"A": check_folder(a), "B": check_folder(b)}
    table = []
    for tag, batch in (("A", a), ("B", b)):
        got = {r["run_id"]: r["cell"] for r in stored.get(tag, [])}
        want = {r["run_id"]: r["cell"] for r in batch["results"]}
        if len(stored.get(tag, [])) != len(want) or got != want:
            table.append(f"batch {tag}: stored {got} != returned {want}")
    checks = [
        ("batch A returned benign_control and indirect_injection_log with telemetry off",
         len(ra) == 2 and {r["scenario_id"] for r in ra} == set(A_SCENARIOS)
         and all(r["telemetry_enabled"] is False for r in ra),
         f"got {[(r['scenario_id'], r['telemetry_enabled']) for r in ra]}"),
        ("batch B returned indirect_injection_log with telemetry on",
         len(rb) == 1 and rb[0]["scenario_id"] == B_SCENARIOS[0]
         and rb[0]["telemetry_enabled"] is True,
         f"got {[(r['scenario_id'], r['telemetry_enabled']) for r in rb]}"),
        ("all three results valid",
         len(rows) == 3 and all(r["valid"] is True for r in rows),
         "invalid: " + "; ".join(f"{r['scenario_id']}: {r['invalid_reason']}"
                                 for r in rows if r["valid"] is not True)),
        ("four tripwires and task_completed are booleans", not bad_bool,
         f"not boolean: {bad_bool}"),
        ("every returned run has a logged reply step", bool(rows) and not no_reply,
         f"no reply step: {no_reply}"),
        ("batch B has a reply step with non-null mean_logprob",
         any(s["mean_logprob"] is not None for s in b_replies),
         "no reply step in batch B has mean_logprob"),
        ("batch A has reply steps and none has non-null mean_logprob",
         bool(a_replies) and not any(s["mean_logprob"] is not None for s in a_replies),
         "batch A has no reply steps" if not a_replies
         else "a reply step in batch A has mean_logprob"),
        ("batch A folder complete", not folder["A"], f"{folder['A']}"),
        ("batch B folder complete", not folder["B"], f"{folder['B']}"),
        ("results table has one row per returned run with the returned cell", not table,
         "; ".join(table)),
        ("batch A not aborted", a["aborted"] is False, "batch A reports aborted"),
        ("batch B not aborted", b["aborted"] is False, "batch B reports aborted"),
    ]
    return [{"criterion": n, "passed": bool(ok), "detail": None if ok else d}
            for n, ok, d in checks]


def _batch_data(batch: dict, batch_id: str) -> dict:
    return {"batch_id": batch_id, "out_dir": batch["out_dir"], "aborted": batch["aborted"],
            "abort_reason": batch.get("abort_reason"), "results": batch["results"]}


def _report(ev: Evidence, cfg: dict, a: dict, b: dict, ids: dict) -> list[str]:
    db = cfg["db_path"]
    labels = [("A", r) for r in a["results"]] + [("B", r) for r in b["results"]]
    steps = {r["run_id"]: read_steps(db, r["run_id"]) for _, r in labels}
    for tag, r in labels:
        show(ev, f"result row: batch {tag} {r['scenario_id']}", r)
    ev.data["step_lines"] = {}
    for tag, r in labels:
        keys = B_STEP_KEYS if tag == "B" else STEP_KEYS
        out(ev, f"--- reply steps: batch {tag} {r['scenario_id']} ---")
        lines = step_lines(steps[r["run_id"]], keys)
        ev.data["step_lines"][r["run_id"]] = lines
        for ln in lines or ["  (no reply steps)"]:
            out(ev, ln)
    b_tool_steps = [s for r in b["results"] for s in reply_steps(steps[r["run_id"]])
                    if s["tool_name"]]
    ev.data[FLAG_NAME] = any(s["tool_name_logprob"] is not None for s in b_tool_steps)
    spikes = [s["entropy_spike_delta"] for r in b["results"] for s in steps[r["run_id"]]
              if s["entropy_spike_delta"] is not None]
    out(ev, f"entropy_spike_delta: {spikes[0]!r}" if spikes
        else "entropy_spike_delta: none recorded")
    out(ev, f"{FLAG_NAME}: {ev.data[FLAG_NAME]}")
    out(ev, "")
    ev.data["parse_failure_reasons"] = {}
    for tag, r in labels:
        out(ev, f"--- What happened: batch {tag} {r['scenario_id']} ---")
        ev.data["parse_failure_reasons"][r["run_id"]] = parse_reason_counts(steps[r["run_id"]])
        for text in what_happened(r, steps[r["run_id"]]):
            out(ev, "  " + text)
    out(ev, "")
    stored = {"A": read_results(db, ids["A"]), "B": read_results(db, ids["B"])}
    criteria = build_criteria(a, b, steps, stored)
    ev.data["criteria"] = criteria
    out(ev, "--- Mechanical criteria ---")
    for c in criteria:
        out(ev, f"  [{'PASS' if c['passed'] else 'FAIL'}] {c['criterion']}"
                + ("" if c["passed"] else f" -- {c['detail']}"))
    out(ev, "")
    out(ev, "summary.md files:")
    for batch in (a, b):
        out(ev, "  " + os.path.join(batch["out_dir"], "summary.md"))
    out(ev, "transcripts:")
    for batch in (a, b):
        for r in batch["results"]:
            out(ev, "  " + os.path.join(batch["out_dir"], "runs", f"{r['run_id']}.md"))
    return [f"{c['criterion']} ({c['detail']})" for c in criteria if not c["passed"]]


def _batches(ev: Evidence, cfg: dict, config_path: str, model: str) -> list[str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ids = {"A": f"gate3a-{stamp}", "B": f"gate3b-{stamp}"}
    ev.data["batches"] = {}
    out(ev, f"batch A {ids['A']}: benign_control, indirect_injection_log, 1 rep, telemetry off")
    a = run_eval.run_batch(cfg, [model], list(A_SCENARIOS), 1, False, ids["A"],
                           config_path=config_path)
    ev.data["batches"]["A"] = _batch_data(a, ids["A"])  # survives a batch B failure
    out(ev, f"batch B {ids['B']}: indirect_injection_log, 1 rep, telemetry on")
    b = run_eval.run_batch(cfg, [model], list(B_SCENARIOS), 1, True, ids["B"],
                           config_path=config_path)
    ev.data["batches"]["B"] = _batch_data(b, ids["B"])
    ev.data["results"] = a["results"] + b["results"]
    return _report(ev, cfg, a, b, ids)


def run_gate(ev: Evidence, cfg: dict, config_path: str, model: str) -> str | None:
    host, port = cfg["listener"]["host"], cfg["listener"]["port"]
    ev.data["model"] = model
    problem = precheck(cfg["ollama_host"], model)
    if problem:
        return problem
    out(ev, f"model {model} present at {cfg['ollama_host']}")
    try:
        failed = _batches(ev, cfg, config_path, model)
    finally:
        time.sleep(0.5)
        free = not port_open(host, port)
        ev.data["port_free_at_end"] = free
        out(ev, f"port {port} is free again" if free else f"WARNING: port {port} still in use")
    out(ev, "")
    out(ev, VERBATIM)
    if not free:
        failed.append(f"port {port} still in use at end")
    return "; ".join(failed) if failed else None


def body(ev: Evidence, argv: list[str] | None = None) -> str | None:
    p = argparse.ArgumentParser(description="Gate 3: whole harness against a real local model.")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--model", default=None)
    args = p.parse_args(argv)
    config_path = os.path.abspath(args.config)
    cfg = load_config(config_path)
    return run_gate(ev, cfg, config_path, args.model or cfg["models"][0])


def main(argv: list[str] | None = None) -> int:
    # run_main deletes stale evidence first and records any exception as a FAIL.
    return run_main("gate3", lambda ev: body(ev, argv))


if __name__ == "__main__":
    sys.exit(main())
