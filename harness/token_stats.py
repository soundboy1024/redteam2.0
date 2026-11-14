"""Token statistics over Ollama's per-token logprob list. Pure functions, math only."""
import math

_KEYS = ("mean_logprob", "min_logprob", "std_logprob", "mean_entropy_approx", "max_entropy_approx")


def _entropy(top_logprobs: list[dict]) -> float:
    """H over the returned alternatives, renormalised to sum to one (an approximation)."""
    if not top_logprobs:
        raise ValueError("position has no top_logprobs; cannot compute entropy")
    # log-sum-exp: shift by the max so an all-underflow position cannot give total == 0.
    m = max(t["logprob"] for t in top_logprobs)
    probs = [math.exp(t["logprob"] - m) for t in top_logprobs]
    total = sum(probs)
    h = -sum((p / total) * math.log(p / total) for p in probs if p > 0)
    return h + 0.0  # normalise -0.0 to 0.0


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

