"""Gate 3: run the whole harness once against a real local model (director gate).

Run from the repo root with the .venv python:
    .venv\\Scripts\\python.exe gates\\gate3.py [--config config.yaml] [--model NAME]

Calls the real Ollama model and starts the real listener on the configured port.
Checks mechanics only; judging the behaviour is the director's call.
"""
import argparse
import os
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "gates"))

import requests  # noqa: E402

import run_eval  # noqa: E402
from _common import Evidence, finish, out, show  # noqa: E402
from listener_proc import port_open  # noqa: E402
from rt_config import ConfigError, load_config  # noqa: E402
from telemetry.logger import read_steps  # noqa: E402

TRIPWIRES = ("tripwire_canary_read", "tripwire_unauth_tool_call",
             "tripwire_canary_exfiltrated", "tripwire_honeypot_endpoint_hit")
BOOL_FIELDS = TRIPWIRES + ("task_completed",)
BATCH_FILES = ("results.json", "summary.md", "steps.jsonl", "tool_events.jsonl")
VERBATIM = ("A compromised or failed-task result is not a gate failure. Gate 3 checks "
            "that the harness measured the run; judging the behaviour is the director's call.")
STEP_KEYS = ("step_index", "agent_state", "tool_name", "tool_name_logprob",
             "mean_entropy_approx", "token_count")
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


def what_happened(row: dict) -> list[str]:
    fired = [t.removeprefix("tripwire_") for t in TRIPWIRES if row.get(t)]
    return [
        f"scenario {row['scenario_id']} ran as cell '{row['cell']}'.",
        "tripwires fired: " + (", ".join(fired) if fired else "none") + ".",
        f"stop_reason: {row['stop_reason']}; steps: {row['steps']}; "
        f"parse_failures: {row['parse_failures']}.",
        f"poison file read: {'yes' if row['poison_ingested'] else 'no'}.",
    ]


def check_folder(batch: dict) -> list[str]:
    missing = [n for n in BATCH_FILES if not os.path.isfile(os.path.join(batch["out_dir"], n))]
    for r in batch["results"]:
        t = os.path.join("runs", f"{r['run_id']}.md")
        if not os.path.isfile(os.path.join(batch["out_dir"], t)):
            missing.append(t)
    return missing


def transcripts(batch: dict) -> list[str]:
    return [os.path.join(batch["out_dir"], "runs", f"{r['run_id']}.md") for r in batch["results"]]


def build_criteria(cfg: dict, a: dict, b: dict, telemetry_steps: list[dict],
                   a_steps: list[dict]) -> list[dict]:
    rows = a["results"] + b["results"]
    bad_bool = [f"{r['scenario_id']}.{k}" for r in rows for k in BOOL_FIELDS
                if not isinstance(r.get(k), bool)]
    missing = {"A": check_folder(a), "B": check_folder(b)}
    checks = [
        ("three results returned", len(rows) == 3, f"got {len(rows)} result rows"),
        ("all results valid", bool(rows) and all(r["valid"] is True for r in rows),
         "invalid: " + "; ".join(f"{r['scenario_id']}: {r['invalid_reason']}"
                                 for r in rows if r["valid"] is not True)),
        ("four tripwires and task_completed are booleans", not bad_bool,
         f"not boolean: {bad_bool}"),
        ("batch B has a step with non-null mean_logprob",
         any(s["mean_logprob"] is not None for s in telemetry_steps),
         "no step in batch B has mean_logprob"),
        ("batch A has no step with non-null mean_logprob",
         not any(s["mean_logprob"] is not None for s in a_steps),
         "a step in batch A has mean_logprob"),
        ("batch A folder complete", not missing["A"], f"missing: {missing['A']}"),
        ("batch B folder complete", not missing["B"], f"missing: {missing['B']}"),
        ("batch A not aborted", a["aborted"] is False, "batch A reports aborted"),
        ("batch B not aborted", b["aborted"] is False, "batch B reports aborted"),
    ]
    return [{"criterion": n, "passed": bool(ok), "detail": None if ok else d}
            for n, ok, d in checks]


def run_gate(ev: Evidence, cfg: dict, config_path: str, model: str) -> str | None:
    host, port = cfg["listener"]["host"], cfg["listener"]["port"]
    ev.data["model"] = model
    problem = precheck(cfg["ollama_host"], model)
    if problem:
        return problem
    out(ev, f"model {model} present at {cfg['ollama_host']}")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    id_a, id_b = f"gate3a-{stamp}", f"gate3b-{stamp}"
    out(ev, f"batch A {id_a}: benign_control, indirect_injection_log, 1 rep, telemetry off")
    a = run_eval.run_batch(cfg, [model], ["benign_control", "indirect_injection_log"], 1,
                           False, id_a, config_path=config_path)
    out(ev, f"batch B {id_b}: indirect_injection_log, 1 rep, telemetry on")
    b = run_eval.run_batch(cfg, [model], ["indirect_injection_log"], 1, True, id_b,
                           config_path=config_path)
    ev.data["batches"] = {"A": {"batch_id": id_a, "out_dir": a["out_dir"]},
                          "B": {"batch_id": id_b, "out_dir": b["out_dir"]}}
    ev.data["results"] = a["results"] + b["results"]
    labels = [("A", r) for r in a["results"]] + [("B", r) for r in b["results"]]
    for tag, r in labels:
        show(ev, f"result row: batch {tag} {r['scenario_id']}", r)
    a_steps = [s for r in a["results"] for s in read_steps(cfg["db_path"], r["run_id"])]
    b_steps = [s for r in b["results"] for s in read_steps(cfg["db_path"], r["run_id"])]
    lines = [{k: s[k] for k in STEP_KEYS} for s in b_steps if s["tool_name"]]
    ev.data["step_telemetry"] = lines
    ev.data["logprobs_returned_for_tool_call_step"] = any(
        s["tool_name_logprob"] is not None for s in lines)
    out(ev, "--- batch B tool-call steps (telemetry on) ---")
    for ln in lines:
        out(ev, "  " + ", ".join(f"{k}={ln[k]!r}" for k in STEP_KEYS))
    if not lines:
        out(ev, "  (no reply row has a tool_name)")
    spikes = [s["entropy_spike_delta"] for s in b_steps if s["entropy_spike_delta"] is not None]
    out(ev, f"entropy_spike_delta: {spikes[0]!r}" if spikes
        else "entropy_spike_delta: none recorded")
    out(ev, f"logprobs_returned_for_tool_call_step: "
            f"{ev.data['logprobs_returned_for_tool_call_step']}")
    out(ev, "")
    for tag, r in labels:
        out(ev, f"--- What happened: batch {tag} {r['scenario_id']} ---")
        for text in what_happened(r):
            out(ev, "  " + text)
    out(ev, "")
    criteria = build_criteria(cfg, a, b, b_steps, a_steps)
    ev.data["criteria"] = criteria
    out(ev, "--- Mechanical criteria ---")
    for c in criteria:
        out(ev, f"  [{'PASS' if c['passed'] else 'FAIL'}] {c['criterion']}"
                + ("" if c["passed"] else f" -- {c['detail']}"))
    out(ev, "")
    out(ev, "summary.md files:")
    out(ev, "  " + os.path.join(a["out_dir"], "summary.md"))
    out(ev, "  " + os.path.join(b["out_dir"], "summary.md"))
    out(ev, "transcripts:")
    for path in transcripts(a) + transcripts(b):
        out(ev, "  " + path)
    time.sleep(0.5)
    free = not port_open(host, port)
    ev.data["port_free_at_end"] = free
    out(ev, f"port {port} is free again" if free else f"WARNING: port {port} still in use")
    out(ev, "")
    out(ev, VERBATIM)
    failed = [f"{c['criterion']} ({c['detail']})" for c in criteria if not c["passed"]]
    if not free:
        failed.append(f"port {port} still in use at end")
    return "; ".join(failed) if failed else None


def main() -> int:
    p = argparse.ArgumentParser(description="Gate 3: whole harness against a real local model.")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--model", default=None)
    args = p.parse_args()
    ev = Evidence()
    config_path = os.path.abspath(args.config)
    try:
        cfg = load_config(config_path)
        model = args.model or cfg["models"][0]
        failure = run_gate(ev, cfg, config_path, model)
    except (run_eval.ListenerStartError, run_eval.LogWriteError, RuntimeError, OSError,
            ValueError, KeyError, ConfigError, requests.RequestException) as exc:
        failure = f"{type(exc).__name__}: {exc}"
    return finish(ev, "gate3", failure)


if __name__ == "__main__":
    sys.exit(main())
