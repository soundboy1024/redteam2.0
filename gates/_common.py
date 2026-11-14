"""Shared plumbing for the gate scripts: evidence collection and the final verdict."""
import json
import math
import os
import traceback
from dataclasses import dataclass, field
from typing import Callable

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(ROOT, "gates", "evidence")


@dataclass
class Evidence:
    lines: list[str] = field(default_factory=list)
    data: dict = field(default_factory=dict)


def out(ev: Evidence, text: str = "") -> None:
    print(text)
    ev.lines.append(text)


def show(ev: Evidence, title: str, row: dict) -> None:
    out(ev, f"--- {title} ---")
    for k, v in row.items():
        out(ev, f"  {k}: {v!r}")


def _jsonable(v):
    """Non-finite floats become their repr and dict keys become strings, so the JSON
    stays valid. A self-containing structure raises RecursionError."""
    if isinstance(v, float):
        return v if math.isfinite(v) else repr(v)
    if isinstance(v, dict):
        return {(k if isinstance(k, str) else str(k)): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


def _one_line(text: str) -> str:
    return " ".join(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"))


def clear_evidence(gate_name: str, evidence_dir: str | None = None) -> None:
    """Delete this gate's previous .txt and .json so stale evidence can never survive."""
    evidence_dir = evidence_dir or EVIDENCE_DIR
    for ext in (".txt", ".json"):
        path = os.path.join(evidence_dir, gate_name + ext)
        if os.path.exists(path):
            os.remove(path)


def _write_both(evidence_dir: str, docs: dict[str, str]) -> None:
    """Write every document to a temp file first, then replace the targets."""
    os.makedirs(evidence_dir, exist_ok=True)
    temps = {}
    try:
        for name, text in docs.items():
            tmp = os.path.join(evidence_dir, f".{name}.{os.getpid()}.tmp")
            temps[name] = tmp
            with open(tmp, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
        for name, tmp in temps.items():
            os.replace(tmp, os.path.join(evidence_dir, name))
    finally:
        for tmp in temps.values():
            if os.path.exists(tmp):
                os.remove(tmp)


def finish(ev: Evidence, gate_name: str, failure: str | None,
           evidence_dir: str | None = None) -> int:
    evidence_dir = evidence_dir or EVIDENCE_DIR
    number = gate_name.removeprefix("gate")
    try:
        data_json = _jsonable(ev.data)
        json.dumps(data_json, allow_nan=False, default=repr)
    except (ValueError, TypeError, RecursionError) as exc:
        data_json = None
        failure = (f"evidence data could not be serialised ({type(exc).__name__}: {exc})"
                   + (f"; original failure: {failure}" if failure is not None else ""))
    doc = {"gate": gate_name, "passed": failure is None, "failure": failure,
           "data": data_json}
    json_text = json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False,
                           default=repr) + "\n"
    out(ev, f"GATE {number}: PASS" if failure is None
        else f"GATE {number}: FAIL {_one_line(failure)}")
    _write_both(evidence_dir, {f"{gate_name}.txt": "\n".join(ev.lines) + "\n",
                               f"{gate_name}.json": json_text})
    return 0 if failure is None else 1


def run_main(gate_name: str, body: Callable[[Evidence], str | None],
             evidence_dir: str | None = None) -> int:
    """Clear stale evidence, run the gate body, and turn any exception into a recorded
    FAIL with its traceback. KeyboardInterrupt is not caught."""
    clear_evidence(gate_name, evidence_dir)
    ev = Evidence()
    try:
        failure = body(ev)
    except Exception as exc:  # recorded failure: written to evidence, exit 1
        failure = f"{type(exc).__name__}: {exc}"
        ev.data["traceback"] = traceback.format_exc()
        out(ev, ev.data["traceback"].rstrip())
    return finish(ev, gate_name, failure, evidence_dir)
