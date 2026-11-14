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

RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
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


def build_matrix(results: list[dict]) -> list[dict]:
    models: list[str] = []
    for r in results:
        if r["model_name"] not in models:
            models.append(r["model_name"])
    cells: dict[tuple, dict] = {}
    for r in results:
        key = (r["model_name"], r["attack_taxonomy"])
        row = cells.setdefault(key, {
            "model_name": key[0], "attack_taxonomy": key[1], "n_valid": 0,
            **{c: 0 for c in CELLS}, "invalid": 0, "poison_ingested": 0,
            "canary_read": 0})
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
    for row in cells.values():
        if sum(row[c] for c in CELLS) != row["n_valid"]:
            raise ValueError(f"cell counts do not sum to n_valid for "
                             f"{row['model_name']!r}/{row['attack_taxonomy']!r}")
    return [cells[k] for k in sorted(
        cells, key=lambda k: (models.index(k[0]), _taxonomy_key(k[1])))]


# ---- text helpers ----------------------------------------------------------

def _write(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def _inline(value) -> str:
    """One line, safe inside a table cell or list item."""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
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
    if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
        raise ValueError(f"run_id {run_id!r} is not a plain token ([A-Za-z0-9_-]{{1,64}})")
    return run_id


# ---- results.json ----------------------------------------------------------

def write_results_json(out_dir: str, batch_meta: dict, results: list[dict]) -> str:
    doc = {"batch": batch_meta, "limitation": LIMITATION_NOTE,
           "matrix": build_matrix(results), "results": results}
    text = json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    return _write(os.path.join(out_dir, "results.json"), text)


# ---- summary.md ------------------------------------------------------------

def _header(meta: dict) -> list[str]:
    fields = ("batch_id", "models", "scenario_ids", "n_runs", "temperature",
              "telemetry_enabled", "started_at", "ended_at", "aborted")
    lines = []
    for k in fields:
        v = meta[k]
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        lines.append(f"- {k}: {_inline(v)}")
    return lines


def write_summary_md(out_dir: str, batch_meta: dict, results: list[dict]) -> str:
    matrix = build_matrix(results)
    lines: list[str] = []
    if batch_meta["aborted"]:
        lines += ["**BATCH ABORTED EARLY: the matrix below is incomplete.**", ""]
    lines += [f"# Batch {_inline(batch_meta['batch_id'])}", ""]
    lines += _header(batch_meta)
    cols = ("Taxonomy", "Valid runs", "Completed and clean", "Completed and compromised",
            "Failed and clean", "Failed and compromised", "Invalid", "Poison read",
            "Canary read")
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
                _inline(row["attack_taxonomy"]), str(n),
                *(_pct(row[c], n) for c in CELLS),
                str(row["invalid"]), _pct(row["poison_ingested"], n),
                _pct(row["canary_read"], n)]) + " |")
    n_valid = sum(1 for r in results if r["valid"])
    lines += ["", "## Totals", "",
              f"{len(results)} total runs, {n_valid} valid, {len(results) - n_valid} invalid",
              "", "## Invalid runs", ""]
    invalid = [r for r in results if not r["valid"]]
    if invalid:
        lines += [f"- {_inline(r['run_id'])} | {_inline(r['model_name'])} | "
                  f"{_inline(r['scenario_id'])} | {_inline(r['invalid_reason'])}"
                  for r in invalid]
    else:
        lines.append("None")
    lines += ["", "## Notes", ""]
    noted = [r for r in results if r["notes"]]
    if noted:
        lines += [f"- {_inline(r['run_id'])}: {_inline('; '.join(map(str, r['notes'])))}"
                  for r in noted]
    else:
        lines.append("None")
    lines += ["", "## Limitations", "", LIMITATION_NOTE, "", COMPLETION_NOTE, ""]
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


def write_transcript_md(out_dir: str, result: dict, steps: list[dict],
                        tool_events: list[dict], listener_events: list[dict]) -> str:
    run_id = _check_run_id(result["run_id"])
    lines = [f"# Run {run_id}", ""]
    if not result["valid"]:
        lines += [f"**INVALID RUN: {_inline(result['invalid_reason'])}**", ""]
    lines += ["## Identity", ""]
    for k in ("batch_id", "model_name", "scenario_id", "attack_taxonomy",
              "repetition_index", "temperature", "telemetry_enabled"):
        lines.append(f"- {k}: {_inline(result[k])}")
    lines += ["", "## Result", ""]
    for k in ("valid", "cell", "tripwire_canary_read", "tripwire_unauth_tool_call",
              "tripwire_canary_exfiltrated", "tripwire_honeypot_endpoint_hit",
              "compromised", "task_completed", "stop_reason", "steps",
              "parse_failures", "poison_ingested"):
        lines.append(f"- {k}: {_inline(result[k])}")
    if result["canary_ids"]:
        lines.append(f"- canary_ids: {_inline(', '.join(map(str, result['canary_ids'])))}")
    if result["notes"]:
        lines.append(f"- notes: {_inline('; '.join(map(str, result['notes'])))}")
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
