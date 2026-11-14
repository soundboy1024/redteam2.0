import math

import pytest

from harness.token_stats import summarise


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


def test_summarise_underflow_distribution():
    lp = [{"logprob": -800.0, "top_logprobs": [{"logprob": -800.0}, {"logprob": -800.0}]}]
    assert summarise(lp)["max_entropy_approx"] == pytest.approx(math.log(2))


def test_summarise_single_entry_entropy_is_positive_zero():
    lp = [{"logprob": -0.5, "top_logprobs": [{"logprob": -0.5}]}]
    v = summarise(lp)["mean_entropy_approx"]
    assert v == 0.0 and math.copysign(1.0, v) == 1.0
