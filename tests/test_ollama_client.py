import json

import pytest
import requests

from harness import ollama_client, tools
from harness.ollama_client import OllamaError, chat

HOST = "http://127.0.0.1:11434"
LOGPROBS = [{"token": "a", "logprob": -0.1, "bytes": [97], "top_logprobs": []}]


class FakeResp:
    def __init__(self, status=200, body=None, text=None):
        self.status_code = status
        self.text = text if text is not None else json.dumps(body)
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


def good_body(**over):
    b = {"message": {"role": "assistant", "content": "hi"}, "done_reason": "stop",
         "eval_count": 10, "eval_duration": 2_000_000_000, "total_duration": 3_000_000_000}
    b.update(over)
    return b


@pytest.fixture
def calls(monkeypatch):
    rec = []

    def install(resp):
        def fake_post(url, json=None, timeout=None, **kw):
            rec.append({"url": url, "json": json, "timeout": timeout})
            if isinstance(resp, Exception):
                raise resp
            return resp
        monkeypatch.setattr(ollama_client._SESSION, "post", fake_post)
        return rec
    return install


def call(telemetry=False, host=HOST):
    return chat(host, "m", [{"role": "user", "content": "x"}], temperature=0.2, seed=7,
                num_ctx=8192, num_predict=512, telemetry=telemetry, timeout_s=30)


def test_request_body_shape(calls):
    rec = calls(FakeResp(body=good_body()))
    call()
    r = rec[0]
    assert r["url"] == HOST + "/api/chat"
    b = r["json"]
    assert b["model"] == "m" and b["stream"] is False and b["messages"]
    assert b["options"] == {"temperature": 0.2, "seed": 7, "num_ctx": 8192, "num_predict": 512}
    assert "tools" not in b and "format" not in b
    assert r["timeout"] == 30


def test_telemetry_on_adds_top_level_fields(calls):
    rec = calls(FakeResp(body=good_body(logprobs=LOGPROBS)))
    res = call(telemetry=True)
    b = rec[0]["json"]
    assert b["logprobs"] is True and b["top_logprobs"] == 20
    assert "logprobs" not in b["options"] and "top_logprobs" not in b["options"]
    assert res.logprobs == LOGPROBS


def test_telemetry_off_omits_them(calls):
    rec = calls(FakeResp(body=good_body()))
    res = call()
    assert "logprobs" not in rec[0]["json"] and "top_logprobs" not in rec[0]["json"]
    assert res.logprobs is None


def test_parses_result(calls):
    calls(FakeResp(body=good_body()))
    res = call()
    assert res.content == "hi" and res.token_count == 10
    assert res.latency_ms == pytest.approx(3000.0)
    assert res.tokens_per_sec == pytest.approx(5.0)
    assert res.done_reason == "stop"


def test_zero_eval_duration_gives_none_rate(calls):
    calls(FakeResp(body=good_body(eval_duration=0)))
    assert call().tokens_per_sec is None


@pytest.mark.parametrize("field", ["eval_count", "eval_duration", "total_duration"])
def test_missing_timing_field_raises(calls, field):
    b = good_body()
    del b[field]
    calls(FakeResp(body=b))
    with pytest.raises(OllamaError, match=field):
        call()


def test_non_200_raises_ollama_error(calls):
    calls(FakeResp(status=500, text="boom happened"))
    with pytest.raises(OllamaError) as e:
        call()
    assert "500" in str(e.value) and "boom happened" in str(e.value)


def test_connection_error_and_timeout_raise_ollama_error(calls):
    calls(requests.ConnectionError("refused"))
    with pytest.raises(OllamaError):
        call()
    calls(requests.Timeout("slow"))
    with pytest.raises(OllamaError):
        call()


def test_missing_message_content_raises_ollama_error(calls):
    calls(FakeResp(body={"message": {"role": "assistant"}}, text="X" * 500))
    with pytest.raises(OllamaError) as e:
        call()
    assert "X" * 300 in str(e.value) and "X" * 301 not in str(e.value)


def test_non_string_content_and_non_json_raise(calls):
    calls(FakeResp(body={"message": {"content": 5}}))
    with pytest.raises(OllamaError):
        call()
    calls(FakeResp(status=200, text="<html>nope</html>"))
    with pytest.raises(OllamaError, match="nope"):
        call()


@pytest.mark.parametrize("lp", [None, "x", {}, []])
def test_telemetry_on_but_no_logprobs_raises_ollama_error(calls, lp):
    b = good_body()
    if lp is not None:
        b["logprobs"] = lp
    calls(FakeResp(body=b))
    with pytest.raises(OllamaError, match="logprobs"):
        call(telemetry=True)


@pytest.mark.parametrize("host", ["http://example.com:11434", "https://127.0.0.1:11434",
                                  "http://127.0.0.1.evil.com", "http://user@evil.com",
                                  "127.0.0.1:11434", "ftp://localhost"])
def test_non_loopback_host_refused(calls, host):
    rec = calls(FakeResp(body=good_body()))
    with pytest.raises(OllamaError):
        call(host=host)
    assert rec == []


def test_localhost_allowed(calls):
    rec = calls(FakeResp(body=good_body()))
    call(host="http://localhost:11434")
    assert rec[0]["url"] == "http://localhost:11434/api/chat"


def test_session_ignores_proxy_env(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:1")
    assert ollama_client._SESSION.trust_env is False
    assert ollama_client._SESSION is not tools._SESSION
