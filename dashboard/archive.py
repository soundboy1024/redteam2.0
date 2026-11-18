"""Read-only view of batches that are not in the current run log (CLAUDE.md 4.8).

A batch recorded under an older run log schema cannot be opened from the run log any
more, but its folder under results/ still holds what was written at the time. This
module reads those files and nothing else. It never grades and never writes.
"""
import json
import os
import re

BATCH_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
RUN_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
RESULTS_FILE = "results.json"
SUMMARY_FILE = "summary.md"
NOTE = ("These batches are not in the current run log. Everything on this page is read "
        "from the files the batch wrote when it ran; nothing is graded again. A batch was "
        "graded under the rules of its time, so an older batch may lack defenses, signals "
        "or the disguised canary forms, and is not comparable with newer ones.")


def list_archived(results_dir: str, current_ids) -> list[str]:
    """Batch folders with a results.json whose id is not in the current run log,
    sorted by name. Folders starting with an underscore are not batches."""
    if not os.path.isdir(results_dir):
        return []
    current = set(current_ids)
    return sorted(
        name for name in os.listdir(results_dir)
        if not name.startswith("_") and BATCH_ID_RE.fullmatch(name) and name not in current
        and os.path.isfile(os.path.join(results_dir, name, RESULTS_FILE)))


def read_archived(results_dir: str, batch_id: str) -> dict:
    """{"batch", "matrix", "results", "limitation", "summary", "problem"} for one
    archived batch. A file that cannot be read gives a problem text, never a guess."""
    if not BATCH_ID_RE.fullmatch(batch_id):
        raise ValueError(f"invalid batch id {batch_id!r}")
    folder = os.path.join(results_dir, batch_id)
    out = {"batch": {}, "matrix": [], "results": [], "limitation": None, "summary": None,
           "problem": None}
    try:
        with open(os.path.join(folder, RESULTS_FILE), encoding="utf-8") as f:
            doc = json.load(f)
        if not isinstance(doc, dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError) as exc:
        out["problem"] = f"{RESULTS_FILE} could not be read: {type(exc).__name__}: {exc}"
        return out
    for key, kind in (("batch", dict), ("matrix", list), ("results", list)):
        value = doc.get(key)
        if isinstance(value, kind):
            out[key] = value
    out["results"] = [r for r in out["results"] if isinstance(r, dict)]
    out["matrix"] = [r for r in out["matrix"] if isinstance(r, dict)]
    if isinstance(doc.get("limitation"), str):
        out["limitation"] = doc["limitation"]
    try:
        with open(os.path.join(folder, SUMMARY_FILE), encoding="utf-8") as f:
            out["summary"] = f.read()
    except OSError as exc:
        out["problem"] = f"{SUMMARY_FILE} could not be read: {type(exc).__name__}: {exc}"
    return out


def read_transcript(results_dir: str, batch_id: str, run_id: str) -> str | None:
    """The stored transcript of one run as text, or None when there is none."""
    if not BATCH_ID_RE.fullmatch(batch_id) or not RUN_ID_RE.fullmatch(str(run_id)):
        raise ValueError(f"invalid batch id or run id: {batch_id!r}, {run_id!r}")
    path = os.path.join(results_dir, batch_id, "runs", f"{run_id}.md")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return f.read()
