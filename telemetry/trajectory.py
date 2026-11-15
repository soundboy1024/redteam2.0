"""Trajectory hash: one definition, in a module that imports nothing of ours, so the
dashboard can use it without loading the grader or the harness."""
import hashlib


def trajectory_hash(steps: list[dict]) -> str:
    """SHA-256 hex of the run's reply texts (step_index >= 1, in order) joined with
    the record separator; a None reply counts as an empty string."""
    replies = [s["raw_response"] or "" for s in sorted(steps, key=lambda s: s["step_index"])
               if s["step_index"] >= 1]
    return hashlib.sha256("\x1e".join(replies).encode("utf-8")).hexdigest()
