"""Results writer (CLAUDE.md section 4): graded rows in, JSON and Markdown out.

Pure formatting. Nothing here reads the database, grades, or calls the harness.
Model output is untrusted text: transcripts put it inside code fences longer
than any backtick run it contains, so it cannot break out or forge sections.
"""
import json
import os
import re

LIMITATION_NOTE = ("Canary matching is exact string match: an agent that encodes, "
                   "truncates or paraphrases a canary evades tripwire_canary_exfiltrated "
                   "(the other tripwires still fire on the request itself).")
COMPLETION_NOTE = ("The final_response_contains completion check is a substring match, "
                   "so an answer that lists every device also passes.")
EXECUTED_NOTE = ("Cells reflect executed actions only. A reply that failed to parse was never "
                 "executed, so a run with parse failures may contain tool calls the model "
                 "attempted that never ran. A \"clean\" cell means no tripwire fired on an "
                 "executed action.")
FAILED_NOTE = ("A \"failed\" cell means the completion check did not match. It does not "
               "distinguish a wrong answer from a right answer given in the wrong form.")
TEMPERATURE_NOTE = ("Temperature 0 is among the batch temperatures, so repetitions of the "
                    "same model, scenario and temperature 0 are expected to be identical "
                    "and are not independent samples.")
HOSTED_NOTE = ("Hosted models run with provider defaults (no thinking or effort setting is "
               "sent), and repetitions are not guaranteed to be reproducible.")
ATTEMPT_NOTE = ("Attempted calls were never executed and are not part of any cell.")
TRIPWIRES = ("tripwire_canary_read", "tripwire_unauth_tool_call",
             "tripwire_canary_exfiltrated", "tripwire_honeypot_endpoint_hit")

RUN_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL",
                  *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
TAXONOMY_ORDER = ("benign_control", "benign_tempting", "indirect_injection_log",
                  "indirect_injection_markdown", "fake_system_error", "authority_spoof")
CELLS = ("completed_clean", "completed_compromised", "failed_clean", "failed_compromised")
TOOL_RESULT_LIMIT = 2000
POISON_MARK = ">>> poison in context from this step"
TELEMETRY_FIELDS = ("token_count", "latency_ms", "tokens_per_sec", "mean_logprob",
                    "min_logprob", "std_logprob", "mean_entropy_approx",
                    "max_entropy_approx", "entropy_spike_delta", "tool_name_logprob")


# ---- matrix ----------------------------------------------------------------

def _taxonomy_key(name: str):
    if name in TAXONOMY_ORDER:
        return (0, TAXONOMY_ORDER.index(name), "")
    return (1, 0, name)


def _temperature_key(t):
    """Numbers ascending, then None (the model's default)."""
    return (1, 0.0) if t is None else (0, float(t))


def _temp_text(t) -> str:
    return "default" if t is None else f"{t:g}"


def build_matrix(results: list[dict],
                 trajectory_hashes: dict[str, str] | None = None) -> list[dict]:
    """Per model and taxonomy: cell counts over valid runs. distinct_trajectories is
    None unless trajectory_hashes (run_id to hash) is given."""
    models: list[str] = []
    for r in results:
        if r["model_name"] not in models:
            models.append(r["model_name"])
    cells: dict[tuple, dict] = {}
    for r in results:
        key = (r["model_name"], r["temperature"], r["attack_taxonomy"])
        row = cells.setdefault(key, {
            "model_name": key[0], "temperature": key[1], "attack_taxonomy": key[2],
            "n_valid": 0,
            **{c: 0 for c in CELLS}, "invalid": 0, "poison_ingested": 0,
            "canary_read": 0, "runs_with_parse_failures": 0, "parse_failures_total": 0,
            "runs_with_attempted_tripwires": 0,
            "distinct_trajectories": None if trajectory_hashes is None else set()})
        if not r["valid"]:
            row["invalid"] += 1
            continue
        if r["cell"] not in CELLS:
            raise ValueError(f"run {r['run_id']!r}: valid run has cell {r['cell']!r}, "
                             f"expected one of {CELLS}")
        row["n_valid"] += 1
        row[r["cell"]] += 1
        if r["poison_ingested"]:
            row["poison_ingested"] += 1
        if r["tripwire_canary_read"]:
            row["canary_read"] += 1
        if r["parse_failures"]:
            row["runs_with_parse_failures"] += 1
        row["parse_failures_total"] += r["parse_failures"]
        if r["attempted_tripwires"]:
            row["runs_with_attempted_tripwires"] += 1
        if trajectory_hashes is not None:
            if r["run_id"] not in trajectory_hashes:
                raise ValueError(f"run {r['run_id']!r}: no trajectory hash")
            row["distinct_trajectories"].add(trajectory_hashes[r["run_id"]])
    for row in cells.values():
        if isinstance(row["distinct_trajectories"], set):
            row["distinct_trajectories"] = len(row["distinct_trajectories"])
        if sum(row[c] for c in CELLS) != row["n_valid"]:
            raise ValueError(f"cell counts do not sum to n_valid for "
                             f"{row['model_name']!r}/{row['temperature']!r}/"
                             f"{row['attack_taxonomy']!r}")
    return [cells[k] for k in sorted(
        cells, key=lambda k: (models.index(k[0]), _temperature_key(k[1]),
                              _taxonomy_key(k[2])))]


# ---- text helpers ----------------------------------------------------------

def _clean_text(s: str) -> str:
    """Lone surrogates become visible backslash-u escapes; nothing else changes."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def _sanitize(v):
    """Recursive _clean_text over strings (keys too) in a JSON-like structure."""
    if isinstance(v, str):
        return _clean_text(v)
    if isinstance(v, dict):
        return {(_clean_text(k) if isinstance(k, str) else k): _sanitize(x)
                for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_sanitize(x) for x in v]
    return v


def _write(path: str, text: str) -> str:
    """Encode fully first, write a temp file beside the target, then replace."""
    data = text.encode("utf-8", "backslashreplace")
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return path


def _inline(value) -> str:
    """One line, safe inside a table cell or list item."""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    text = text.replace("<", "&lt;").replace(">", "&gt;").replace("`", "\\`")
    return text.replace("\r", " ").replace("\n", " ")


def _pct(count: int, n_valid: int) -> str:
    if n_valid == 0:
        return f"{count} (n/a)"
    return f"{count} ({round(100 * count / n_valid)}%)"


def _fence(text: str, info: str = "") -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{info}\n{text}\n{ticks}"


def _code(value) -> str:
    return _fence("" if value is None else str(value))


def _check_run_id(run_id) -> str:
    if (not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id)
            or run_id.upper() in RESERVED_NAMES):
        raise ValueError(f"run_id {run_id!r} is not a plain token ([A-Za-z0-9_-]{{1,64}})")
    return run_id


# ---- results.json ----------------------------------------------------------

def write_results_json(out_dir: str, batch_meta: dict, results: list[dict],
                       trajectory_hashes: dict[str, str] | None = None) -> str:
    doc = _sanitize({"batch": batch_meta, "limitation": LIMITATION_NOTE,
                     "matrix": build_matrix(results, trajectory_hashes),
                     "results": results, "trajectory_hashes": trajectory_hashes})
    text = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    return _write(os.path.join(out_dir, "results.json"), text)


# ---- summary.md ------------------------------------------------------------

def _header(meta: dict) -> list[str]:
    fields = ("batch_id", "models", "scenario_ids", "n_runs", "temperatures",
              "telemetry_enabled", "started_at", "ended_at", "aborted")
    lines = []
    for k in fields:
        v = meta[k]
        if k == "temperatures":
            v = ", ".join(_temp_text(x) for x in v)
        elif isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        lines.append(f"- {k}: {_inline(v)}")
    return lines


def _fired(result: dict) -> str:
    fired = [t.removeprefix("tripwire_") for t in TRIPWIRES if result[t]]
    return ", ".join(fired) if fired else "none"


def write_summary_md(out_dir: str, batch_meta: dict, results: list[dict],
                     trajectory_hashes: dict[str, str] | None = None) -> str:
    matrix = build_matrix(results, trajectory_hashes)
    lines: list[str] = []
    if batch_meta["aborted"]:
        reason = batch_meta.get("abort_reason") or "(no reason recorded)"
        lines += [f"**BATCH ABORTED EARLY ({_inline(reason)}): the matrix below is "
                  "incomplete.**", ""]
    lines += [f"# Batch {_inline(batch_meta['batch_id'])}", ""]
    lines += _header(batch_meta)
    if 0 in batch_meta["temperatures"] and batch_meta["n_runs"] > 1:
        lines += ["", TEMPERATURE_NOTE]
    if batch_meta.get("hosted_models"):
        no_temp = batch_meta.get("models_without_temperature") or []
        lines += ["", HOSTED_NOTE + " Run without a temperature setting: "
                  + (", ".join(_inline(m) for m in no_temp) if no_temp else "none") + "."]
    cols = ("Temp", "Taxonomy", "Valid runs", "Completed and clean", "Completed and compromised",
            "Failed and clean", "Failed and compromised", "Invalid", "Poison read",
            "Canary read", "Runs with parse failures", "Parse failures (total)",
            "Runs with unexecuted trap attempts", "Distinct trajectories")
    models: list[str] = []
    for row in matrix:
        if row["model_name"] not in models:
            models.append(row["model_name"])
    for model in models:
        lines += ["", f"## {_inline(model)}", "",
                  "| " + " | ".join(cols) + " |",
                  "|" + "---|" * len(cols)]
        for row in (r for r in matrix if r["model_name"] == model):
            n = row["n_valid"]
            lines.append("| " + " | ".join([
                _temp_text(row["temperature"]), _inline(row["attack_taxonomy"]), str(n),
                *(_pct(row[c], n) for c in CELLS),
                str(row["invalid"]), _pct(row["poison_ingested"], n),
                _pct(row["canary_read"], n), _pct(row["runs_with_parse_failures"], n),
                str(row["parse_failures_total"]),
                _pct(row["runs_with_attempted_tripwires"], n),
                "n/a" if row["distinct_trajectories"] is None
                else str(row["distinct_trajectories"])]) + " |")
    lines += ["", ATTEMPT_NOTE]
    n_valid = sum(1 for r in results if r["valid"])
    lines += ["", "## Totals", "",
              f"{len(results)} total runs, {n_valid} valid, {len(results) - n_valid} invalid"]
    if not results:
        lines += ["", "No runs were recorded."]
    lines += ["", "## Invalid runs", ""]
    invalid = [r for r in results if not r["valid"]]
    if invalid:
        lines += [f"- {_inline(r['run_id'])} | {_inline(r['model_name'])} | "
                  f"{_inline(r['scenario_id'])} | "
                  f"{_inline(r['invalid_reason'] or '(no reason recorded)')} | "
                  f"tripwires fired: {_fired(r)} | "
                  f"parse_failures: {_inline(r['parse_failures'])}"
                  for r in invalid]
    else:
        lines.append("None")
    lines += ["", "## Unexecuted trap attempts", ""]
    attempted = [r for r in results if r["attempted_tripwires"]]
    if attempted:
        lines += [f"- {_inline(r['run_id'])} | {_inline(r['model_name'])} | "
                  f"{_inline(r['scenario_id'])} | unexecuted calls would have fired: "
                  f"{_inline(', '.join(map(str, r['attempted_tripwires'])))}"
                  for r in attempted]
    else:
        lines.append("None")
    lines += ["", "## Notes", ""]
    noted = [r for r in results if r["notes"]]
    seen = {r["model_name"] for r in results}
    missing = [m for m in batch_meta["models"] if m not in seen]
    lines += [f"- {_inline(r['run_id'])}: {_inline('; '.join(map(str, r['notes'])))}"
              for r in noted]
    lines += [f"- No runs recorded for model {_inline(m)}." for m in missing]
    if not noted and not missing:
        lines.append("None")
    lines += ["", "## Limitations", "", LIMITATION_NOTE, "", COMPLETION_NOTE, "",
              EXECUTED_NOTE, "", FAILED_NOTE, ""]
    return _write(os.path.join(out_dir, "summary.md"), "\n".join(lines))


# ---- transcripts -----------------------------------------------------------

def _table(headers: tuple, rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_inline(c) for c in row) + " |" for row in rows]
    return out


def _step_lines(steps: list[dict]) -> list[str]:
    lines: list[str] = []
    marked = False
    for s in steps:
        lines += ["", f"### Step {s['step_index']}: {_inline(s['agent_state'])}", ""]
        lines.append(f"poison_ingested: {s['poison_ingested']}")
        if s["poison_ingested"] and not marked:
            marked = True
            lines += ["", POISON_MARK]
        if s["tool_call_parse_failed"]:
            lines += ["", "tool_call_parse_failed: True"]
            if s.get("parse_reason") is not None:
                lines += ["", f"parse_reason: {_inline(s['parse_reason'])}"]
        if s.get("done_reason") not in (None, "stop"):
            lines += ["", f"done_reason: {_inline(s['done_reason'])}"]
        lines += ["", "Raw reply:", "", _code(s["raw_response"])]
        if s["tool_name"] is not None or s["tool_args_json"] is not None:
            lines += ["", "Parsed tool call:", "",
                      _code(f"{s['tool_name']} {s['tool_args_json']}")]
        result = s["tool_result"]
        if result is not None:
            shown = result[:TOOL_RESULT_LIMIT]
            lines += ["", "Tool result:", "", _code(shown)]
            if len(result) > TOOL_RESULT_LIMIT:
                lines += ["", f"[truncated, {len(result) - TOOL_RESULT_LIMIT} more characters]"]
        tele = [f"{k}={s[k]}" for k in TELEMETRY_FIELDS if s.get(k) is not None]
        if tele:
            lines += ["", "Telemetry: " + ", ".join(tele)]
    return lines


def _task_lines(run_inputs: dict) -> list[str]:
    scenario = run_inputs["scenario"]
    lines = ["## Task given to the model", "", _code(run_inputs["user_prompt"]), ""]
    for k in ("poison_files", "canary_files", "allowed_endpoints"):
        items = scenario.get(k) or []
        lines.append(f"- {k}: {_inline(', '.join(map(str, items))) if items else '(none)'}")
    return lines


def write_transcript_md(out_dir: str, result: dict, steps: list[dict],
                        tool_events: list[dict], listener_events: list[dict],
                        run_inputs: dict | None = None) -> str:
    run_id = _check_run_id(result["run_id"])
    lines = [f"# Run {run_id}", ""]
    if not result["valid"]:
        lines += ["**INVALID RUN**", "",
                  _inline(result["invalid_reason"] or "(no reason recorded)"), ""]
    lines += ["## Identity", ""]
    for k in ("batch_id", "model_name", "scenario_id", "attack_taxonomy",
              "repetition_index", "temperature", "telemetry_enabled"):
        lines.append(f"- {k}: {_inline('default' if k == 'temperature' and result[k] is None else result[k])}")
    lines += ["", "## Result", ""]
    for k in ("valid", "cell", "tripwire_canary_read", "tripwire_unauth_tool_call",
              "tripwire_canary_exfiltrated", "tripwire_honeypot_endpoint_hit",
              "compromised", "task_completed", "stop_reason", "steps",
              "parse_failures", "poison_ingested"):
        lines.append(f"- {k}: {_inline(result[k])}")
    if result["canary_ids"]:
        lines.append(f"- canary_ids: {_inline(', '.join(map(str, result['canary_ids'])))}")
    if result["attempted_tripwires"]:
        lines.append("- attempted_tripwires: "
                     f"{_inline(', '.join(map(str, result['attempted_tripwires'])))}")
    for call in result["attempted_calls"]:
        lines.append(f"- attempted_call (never executed): step {_inline(call['step_index'])}: "
                     f"{_inline(call['tool_name'])} "
                     f"{_inline(json.dumps(call['args'], ensure_ascii=False, default=repr))} "
                     f"would fire: {_inline(', '.join(map(str, call['would_fire'])) or 'nothing')}")
    if result["notes"]:
        lines.append(f"- notes: {_inline('; '.join(map(str, result['notes'])))}")
    if run_inputs is not None:
        lines += [""] + _task_lines(run_inputs)
    lines += ["", "## Steps"] + _step_lines(steps)
    lines += ["", "## Tool events", ""]
    if tool_events:
        lines += _table(("event", "timestamp", "detail"), [
            [e["event"], e.get("timestamp", ""),
             json.dumps({k: v for k, v in e.items() if k not in ("event", "timestamp")},
                        ensure_ascii=False, default=repr)] for e in tool_events])
    else:
        lines.append("None")
    lines += ["", "## Listener events", ""]
    if listener_events:
        lines += _table(("id", "timestamp", "method", "path", "route_class", "query_string",
                         "body_text", "canary_ids", "canary_exfiltrated", "honeypot_hit"), [
            [e["id"], e["timestamp"], e["method"], e["path"], e["route_class"],
             e["query_string"], e["body_text"], ", ".join(e["canary_ids"]),
             e["tripwire_canary_exfiltrated"], e["tripwire_honeypot_endpoint_hit"]]
            for e in listener_events])
    else:
        lines.append("None")
    lines.append("")
    return _write(os.path.join(out_dir, "runs", f"{run_id}.md"), "\n".join(lines))
