"""Shared test setup: no test reads this machine's free memory or asks a real Ollama
which model builds are installed. Tests of those two functions replace them again."""
import pytest

import run_eval

PLENTY = 64 * 2 ** 30


@pytest.fixture(autouse=True)
def _no_machine_probes(monkeypatch):
    monkeypatch.setattr(run_eval, "free_memory_bytes", lambda: PLENTY)
    monkeypatch.setattr(
        run_eval, "model_digests",
        lambda cfg, models: {m: f"digest-of-{m}" for m in models if run_eval.is_local(m)})
