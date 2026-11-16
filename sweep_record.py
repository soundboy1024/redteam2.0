"""Model sweep: the queue file, the fit record and the done markers (CLAUDE.md 4.9).

Nothing here talks to Ollama or starts a process, and nothing here imports harness/,
traps/ or telemetry/.
"""
import datetime
import json
import os
import re

import yaml

STATUSES = ("completed", "does_not_fit", "pull_failed", "load_failed", "batch_failed",
            "stopped_for_memory", "stopped")
FLOORS = ("min_free_disk_gb", "min_free_memory_gb", "stop_free_memory_gb")
RECORD_FIELDS = ("digest", "download_size", "pulled_by_sweep", "status", "reason", "backend",
                 "gpu_share", "size_in_memory", "tokens_per_s", "free_memory_after_load",
                 "lowest_free_memory", "seconds", "deleted", "installed_after",
                 "batch_left_running")
LIMITATION = (
    "Canary matching is exact string match: an agent that encodes, truncates or paraphrases "
    "a canary evades tripwire_canary_exfiltrated. fake_system_error and authority_spoof name "
    "the poison file in the user prompt, so their results are not comparable with "
    "indirect_injection_log and indirect_injection_markdown. A model's results are in its "
    "batch folders; this file records whether each model could be run at all.")
GB = 2 ** 30


class QueueError(ValueError):
    pass


def slug(tag: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", tag.lower()).strip("-")


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def load_queue(path: str) -> dict:
    if not os.path.exists(path):
        raise QueueError(f"queue file {path} does not exist")
    with open(path, encoding="utf-8") as f:
        try:
            raw = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise QueueError(f"queue file {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise QueueError(f"queue file {path} must be a mapping with models and the floors")
    for key in ("models",) + FLOORS:
        if key not in raw:
            raise QueueError(f"queue file {path} is missing {key}")
    models = raw["models"]
    if not isinstance(models, list) or not models:
        raise QueueError("models must be a non-empty list of model tags")
    seen: dict[str, str] = {}
    for tag in models:
        if not isinstance(tag, str) or not tag.strip() or not slug(tag):
            raise QueueError(f"models: {tag!r} is not a model tag")
        if tag in seen.values():
            raise QueueError(f"models: duplicate tag {tag!r}")
        if slug(tag) in seen:
            raise QueueError(f"models: {tag!r} and {seen[slug(tag)]!r} would get the same name "
                             f"in batch ids ({slug(tag)})")
        seen[slug(tag)] = tag
    for key in FLOORS:
        if not _is_number(raw[key]) or raw[key] <= 0:
            raise QueueError(f"{key} must be a number above 0, got {raw[key]!r}")
    if raw["stop_free_memory_gb"] >= raw["min_free_memory_gb"]:
        raise QueueError("stop_free_memory_gb must be below min_free_memory_gb")
    return {"models": list(models), **{k: raw[k] for k in FLOORS}}


def new_record(tag: str) -> dict:
    record = {"tag": tag, "attempt": 1}
    record.update({field: None for field in RECORD_FIELDS})
    record["batches"] = []
    return record


def sweep_dir(results_dir: str, sweep_id: str) -> str:
    return os.path.join(results_dir, "_sweep", sweep_id)


def _marker(sdir: str, tag: str) -> str:
    return os.path.join(sdir, "done", slug(tag) + ".done")


def is_done(sdir: str, tag: str) -> bool:
    return os.path.exists(_marker(sdir, tag))


def mark_done(sdir: str, tag: str) -> None:
    path = _marker(sdir, tag)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(tag + "\n")


def read_records(sdir: str) -> list[dict]:
    path = os.path.join(sdir, "sweep.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"{path} (sweep.json) is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("records"), list):
        raise ValueError(f"{path} (sweep.json) has no records list")
    return doc["records"]


def upsert(records: list[dict], record: dict) -> list[dict]:
    if any(r["tag"] == record["tag"] for r in records):
        return [record if r["tag"] == record["tag"] else r for r in records]
    return records + [record]


def _replace(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _gb(value) -> str:
    return "" if value is None else f"{value / GB:.1f}"


def _cell(value) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("|", "/").split())


def _markdown(sweep_id: str, records: list[dict], stopped_reason: str | None) -> str:
    lines = [f"# Model sweep {sweep_id}", ""]
    if stopped_reason:
        lines += [f"**The sweep stopped early:** {_cell(stopped_reason)}", ""]
    lines += ["| Model | Status | Reason | Backend | GPU share | In memory (GB) | Tokens/s | "
              "Lowest free memory (GB) | Runs valid / invalid | Deleted |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for r in records:
        valid = sum(b.get("valid") or 0 for b in r["batches"])
        invalid = sum(b.get("invalid") or 0 for b in r["batches"])
        share = "" if r["gpu_share"] is None else f"{r['gpu_share']:.0%}"
        speed = "" if r["tokens_per_s"] is None else f"{r['tokens_per_s']:.1f}"
        deleted = {True: "yes", False: "no", None: ""}[r["deleted"]]
        lines.append("| " + " | ".join([
            _cell(r["tag"]), _cell(r["status"]), _cell(r["reason"]), _cell(r["backend"]),
            share, _gb(r["size_in_memory"]), speed, _gb(r["lowest_free_memory"]),
            f"{valid} / {invalid}", deleted]) + " |")
    lines += ["", "## Limitations", "", LIMITATION, ""]
    return "\n".join(lines)


def write_records(sdir: str, sweep_id: str, records: list[dict],
                  stopped_reason: str | None = None) -> None:
    os.makedirs(sdir, exist_ok=True)
    doc = {"sweep_id": sweep_id,
           "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "stopped_reason": stopped_reason, "limitation": LIMITATION, "records": records}
    _replace(os.path.join(sdir, "sweep.json"), json.dumps(doc, indent=2) + "\n")
    _replace(os.path.join(sdir, "sweep.md"), _markdown(sweep_id, records, stopped_reason))
