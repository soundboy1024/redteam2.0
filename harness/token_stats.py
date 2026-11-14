"""Token statistics over Ollama's per-token logprob list. Pure functions, math only."""
import math

_KEYS = ("mean_logprob", "min_logprob", "std_logprob", "mean_entropy_approx", "max_entropy_approx")


def _entropy(top_logprobs: list[dict]) -> float:
    """H over the returned alternatives, renormalised to sum to one (an approximation)."""
    if not top_logprobs:
        raise ValueError("position has no top_logprobs; cannot compute entropy")
    probs = [math.exp(t["logprob"]) for t in top_logprobs]
    total = sum(probs)
    return -sum((p / total) * math.log(p / total) for p in probs if p > 0)


def summarise(logprobs: list[dict] | None) -> dict:
    if not logprobs:
        return {k: None for k in _KEYS}
    lps = [e["logprob"] for e in logprobs]
    mean = sum(lps) / len(lps)
    var = sum((x - mean) ** 2 for x in lps) / len(lps)
    ents = [_entropy(e.get("top_logprobs") or []) for e in logprobs]
    return {
        "mean_logprob": mean,
        "min_logprob": min(lps),
        "std_logprob": math.sqrt(var),
        "mean_entropy_approx": sum(ents) / len(ents),
        "max_entropy_approx": max(ents),
    }


def logprob_at_text(logprobs: list[dict], content: str, needle: str) -> float | None:
    """Logprob of the first token overlapping the first occurrence of needle, else None."""
    if not needle:
        return None
    concat = "".join(e["token"] for e in logprobs)
    # Some runtimes trim whitespace, so token text may differ from content.
    text = content if concat == content else concat
    start = text.find(needle)
    if start < 0:
        return None
    pos = 0
    for e in logprobs:
        end = pos + len(e["token"])
        if pos <= start < end:
            return e["logprob"]
        pos = end
    return None
