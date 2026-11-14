import math

import pytest

from harness.token_stats import logprob_at_text, summarise


def test_summarise_known_values():
    lp = [{"logprob": -0.1, "top_logprobs": [{"logprob": math.log(0.5)}, {"logprob": math.log(0.5)}]},
          {"logprob": -0.3, "top_logprobs": [{"logprob": 0.0}]}]
    s = summarise(lp)
    assert s["mean_logprob"] == pytest.approx(-0.2) and s["min_logprob"] == pytest.approx(-0.3)
    assert s["std_logprob"] == pytest.approx(0.1)
    assert s["max_entropy_approx"] == pytest.approx(math.log(2))
    assert s["mean_entropy_approx"] == pytest.approx(math.log(2) / 2)


def test_summarise_renormalises_truncated_distribution():
    lp = [{"logprob": -1.0, "top_logprobs": [{"logprob": math.log(0.2)}, {"logprob": math.log(0.2)}]}]
    assert summarise(lp)["max_entropy_approx"] == pytest.approx(math.log(2))


def test_summarise_none_and_empty():
    keys = {"mean_logprob", "min_logprob", "std_logprob", "mean_entropy_approx", "max_entropy_approx"}
    for v in (None, []):
        s = summarise(v)
        assert set(s) == keys and all(x is None for x in s.values())


def test_summarise_empty_top_logprobs_raises():
    with pytest.raises(ValueError):
        summarise([{"logprob": -0.1, "top_logprobs": []}])


def toks(*pairs):
    return [{"token": t, "logprob": lp} for t, lp in pairs]


TOKENS = toks(('{"', -0.1), ("tool", -0.2), ('":', -0.3), (' "', -0.4), ("read", -0.5),
              ("_workspace", -0.6), ("_file", -0.7), ('",', -0.8))
CONTENT = '{"tool": "read_workspace_file",'


def test_logprob_at_text():
    assert logprob_at_text(TOKENS, CONTENT, "read_workspace_file") == -0.5


def test_logprob_at_text_overlap_mid_token():
    t = toks(("ab", -1.0), ("cd", -2.0))
    assert logprob_at_text(t, "abcd", "bc") == -1.0


def test_logprob_at_text_absent_returns_none():
    assert logprob_at_text(TOKENS, CONTENT, "nonexistent") is None


def test_logprob_at_text_trimmed_whitespace_fallback():
    t = toks(("hello", -1.0), (" world", -2.0))
    assert logprob_at_text(t, "  hello world", "world") == -2.0


def test_logprob_at_text_needle_only_in_content_returns_none():
    t = toks(("hello", -1.0))
    assert logprob_at_text(t, "hello world", "world") is None
