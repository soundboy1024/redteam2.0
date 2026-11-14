"""Shared plumbing for the gate scripts: evidence collection and the final verdict."""
import json
import math
import os
from dataclasses import dataclass, field

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


def _finite(v):
    """Replace non-finite floats with their repr so the JSON stays valid."""
    if isinstance(v, float):
        return v if math.isfinite(v) else repr(v)
    if isinstance(v, dict):
        return {k: _finite(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_finite(x) for x in v]
    return v


def finish(ev: Evidence, gate_name: str, failure: str | None,
           evidence_dir: str = EVIDENCE_DIR) -> int:
    number = gate_name.removeprefix("gate")
    out(ev, f"GATE {number}: PASS" if failure is None else f"GATE {number}: FAIL {failure}")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, f"{gate_name}.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(ev.lines) + "\n")
    doc = {"gate": gate_name, "passed": failure is None, "failure": failure,
           "data": _finite(ev.data)}
    with open(os.path.join(evidence_dir, f"{gate_name}.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False, allow_nan=False, default=repr)
        f.write("\n")
    return 0 if failure is None else 1
