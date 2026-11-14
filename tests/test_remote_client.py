import json
import logging

import pytest
import requests

from harness import remote_client
from harness.ollama_client import ModelError, OllamaError
from harness.remote_client import (PROVIDERS, RemoteModelError, accepts_temperature, chat,
                                   list_models, split_model)

KEY = "sk-test-key"
MSGS = [{"role": "system", "content": "SYS"}, {"role": "user", "content": "hello"}]
ANTHROPIC = "anthropic/claude-haiku-5-5"
GROQ = "groq/some-model"


class FakeResp:
    def __init__(self, status=200, body=None, text=None, headers=None):
        self.status_code = status
        self.text = text if text is not None else json.dumps(body)
        self.headers = headers or {}
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


def anthropic_body(content=None, stop="end_turn", **over):
    b = {"content": [{"type": "text", "text": '{"final": "x"}'}] if content is None else content,
         "stop_reason": stop, "usage": {"input_tokens": 11, "output_tokens": 5}}
    b.update(over)
    return b


def openai_body(content="hi", finish="stop", **over):
    b = {"choices": [{"message": {"role": "assistant", "content": content},
                      "finish_reason": finish}],
         "usage": {"prompt_tokens": 9, "completion_tokens": 4}}
    b.update(over)
    return b


@pytest.fixture
def session(monkeypatch):
    """Install a scripted fake session; returns the list of recorded calls."""
    calls = []

    def install(*responses):
        queue = list(responses)

        def fake(method):
            def call(url, **kw):
                calls.append({"method": method, "url": url, **kw})
                item = queue.pop(0)
                if isinstance(item, BaseException):
                    raise item
                return item
            return call
        monkeypatch.setattr(remote_client._SESSION, "post", fake("post"))
        monkeypatch.setattr(remote_client._SESSION, "get", fake("get"))
        calls.clear()
        return calls
    return install


def run(model=ANTHROPIC, temperature=None, sleeps=None):
    sleeps = [] if sleeps is None else sleeps
    return chat(model, MSGS, temperature=temperature, seed=3, max_tokens=4096, timeout_s=30,
                api_key=KEY, sleep=sleeps.append)


def test_session_is_isolated():
    assert remote_client._SESSION.trust_env is False


def test_error_hierarchy():
    assert issubclass(RemoteModelError, ModelError) and issubclass(OllamaError, ModelError)


def test_providers_constants():
    assert PROVIDERS["anthropic"] == {
        "chat_url": "https://api.anthropic.com/v1/messages",
        "models_url": "https://api.anthropic.com/v1/models", "key_env": "ANTHROPIC_API_KEY"}
    assert PROVIDERS["groq"] == {
        "chat_url": "https://api.groq.com/openai/v1/chat/completions",
        "models_url": "https://api.groq.com/openai/v1/models", "key_env": "GROQ_API_KEY"}
    assert PROVIDERS["cerebras"] == {
        "chat_url": "https://api.cerebras.ai/v1/chat/completions",
        "models_url": "https://api.cerebras.ai/v1/models", "key_env": "CEREBRAS_API_KEY"}


@pytest.mark.parametrize("name,expected", [
    ("anthropic/claude-haiku-5-5", ("anthropic", "claude-haiku-5-5")),
    ("groq/llama/x", ("groq", "llama/x")),
    ("cerebras/m", ("cerebras", "m")),
    ("llama3.2:3b", (None, "llama3.2:3b")),
    ("hf.co/org/model", (None, "hf.co/org/model")),
    ("openai/x", (None, "openai/x")),
])
def test_split_model(name, expected):
    assert split_model(name) == expected


@pytest.mark.parametrize("name,expected", [
    ("llama3.2:3b", True), ("hf.co/org/model", True), ("groq/x", True), ("cerebras/x", True),
    ("anthropic/claude-haiku-4-5", True), ("anthropic/claude-sonnet-4-6", True),
    ("anthropic/claude-opus-4-6", True), ("anthropic/claude-haiku-5-5", False),
    ("anthropic/claude-opus-5-5", False), ("anthropic/other", False),
])
def test_accepts_temperature(name, expected):
    assert accepts_temperature(name) is expected


def test_anthropic_request_shape(session):
    calls = session(FakeResp(body=anthropic_body()))
    run()
    c = calls[0]
    assert c["url"] == "https://api.anthropic.com/v1/messages"
    assert c["headers"]["x-api-key"] == KEY
    assert c["headers"]["anthropic-version"] == "2023-06-01"
    assert c["headers"]["content-type"] == "application/json"
    assert c["allow_redirects"] is False and c["timeout"] == 30
    b = c["json"]
    assert b["model"] == "claude-haiku-5-5" and b["max_tokens"] == 4096
    assert b["system"] == "SYS"
    assert b["messages"] == [{"role": "user", "content": "hello"}]
    assert "temperature" not in b
    assert set(b) == {"model", "max_tokens", "system", "messages"}


def test_anthropic_temperature_sent_when_given(session):
    calls = session(FakeResp(body=anthropic_body()))
    run(model="anthropic/claude-haiku-4-5", temperature=0.3)
    assert calls[0]["json"]["temperature"] == 0.3


def test_anthropic_reply_skips_thinking_blocks(session):
    session(FakeResp(body=anthropic_body(content=[
        {"type": "thinking", "thinking": ""},
        {"type": "text", "text": '{"final": "x"}'}])))
    r = run()
    assert r.content == '{"final": "x"}' and r.done_reason == "stop"
    assert r.token_count == 5 and r.prompt_token_count == 11 and r.logprobs is None


def test_anthropic_concatenates_text_blocks(session):
    session(FakeResp(body=anthropic_body(content=[
        {"type": "text", "text": "a"}, {"type": "text", "text": "b"}])))
    assert run().content == "ab"


@pytest.mark.parametrize("stop,expected", [
    ("end_turn", "stop"), ("stop_sequence", "stop"), ("max_tokens", "length"),
    ("tool_use", "tool_use"), ("refusal", "refusal")])
def test_anthropic_done_reason(session, stop, expected):
    session(FakeResp(body=anthropic_body(stop=stop)))
    assert run().done_reason == expected


def test_anthropic_refusal_is_a_reply(session):
    session(FakeResp(body=anthropic_body(content=[], stop="refusal")))
    r = run()
    assert r.content == "" and r.done_reason == "refusal"


def test_openai_request_and_reply(session):
    calls = session(FakeResp(body=openai_body(content=None)))
    r = run(model=GROQ, temperature=0.7)
    c = calls[0]
    assert c["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert c["headers"]["Authorization"] == f"Bearer {KEY}"
    assert c["allow_redirects"] is False
    assert c["json"] == {"model": "some-model", "messages": MSGS, "max_tokens": 4096,
                         "seed": 3, "stream": False, "temperature": 0.7}
    assert r.content == "" and r.done_reason == "stop"
    assert r.token_count == 4 and r.prompt_token_count == 9 and r.logprobs is None


def test_openai_no_temperature_key_when_none(session):
    calls = session(FakeResp(body=openai_body(finish="length")))
    r = run(model="cerebras/m")
    assert "temperature" not in calls[0]["json"] and r.done_reason == "length"
    assert calls[0]["url"] == "https://api.cerebras.ai/v1/chat/completions"


def test_latency_and_tokens_per_sec(session, monkeypatch):
    session(FakeResp(body=openai_body()))
    ticks = iter([10.0, 12.0])
    monkeypatch.setattr(remote_client.time, "perf_counter", lambda: next(ticks))
    r = run(model=GROQ)
    assert r.latency_ms == 2000.0 and r.tokens_per_sec == 2.0


def test_tokens_per_sec_none_when_zero_tokens(session):
    session(FakeResp(body=openai_body(usage={"prompt_tokens": 1, "completion_tokens": 0})))
    assert run(model=GROQ).tokens_per_sec is None


def test_retry_then_success(session):
    calls = session(FakeResp(429, text="slow", headers={"retry-after": "3"}),
                    FakeResp(body=openai_body()))
    sleeps = []
    run(model=GROQ, sleeps=sleeps)
    assert sleeps == [3] and len(calls) == 2


def test_retry_after_capped(session):
    session(FakeResp(429, text="slow", headers={"retry-after": "600"}),
            FakeResp(body=openai_body()))
    sleeps = []
    run(model=GROQ, sleeps=sleeps)
    assert sleeps == [60]


def test_retry_default_schedule_and_logging(session, caplog):
    session(FakeResp(503, text="x"), FakeResp(529, text="x"), FakeResp(500, text="x"),
            requests.ConnectionError("down"), FakeResp(body=openai_body()))
    sleeps = []
    with caplog.at_level(logging.WARNING):
        run(model=GROQ, sleeps=sleeps)
    assert sleeps == [2, 4, 8, 16]
    assert "groq" in caplog.text and "503" in caplog.text and KEY not in caplog.text


def test_retry_exhausted(session):
    calls = session(*[FakeResp(429, text="slow")] * 5)
    sleeps = []
    with pytest.raises(RemoteModelError) as e:
        run(model=GROQ, sleeps=sleeps)
    assert len(calls) == 5 and len(sleeps) == 4 and "429" in str(e.value)


def test_timeout_is_retried(session):
    session(requests.Timeout("slow"), FakeResp(body=openai_body()))
    sleeps = []
    run(model=GROQ, sleeps=sleeps)
    assert sleeps == [2]


def test_non_retryable_status(session):
    calls = session(FakeResp(400, text="bad request " + "z" * 500))
    sleeps = []
    with pytest.raises(RemoteModelError) as e:
        run(sleeps=sleeps)
    assert sleeps == [] and len(calls) == 1
    assert "400" in str(e.value) and "z" * 200 in str(e.value) and "z" * 400 not in str(e.value)


def test_html_body(session):
    session(FakeResp(200, text="<html>nope</html>"))
    with pytest.raises(RemoteModelError, match="not valid JSON"):
        run()


@pytest.mark.parametrize("body", [
    {}, {"content": "x", "stop_reason": "end_turn", "usage": {}},
    {"content": [], "stop_reason": "end_turn"},
    {"content": [], "usage": {"input_tokens": 1, "output_tokens": 1}},
    {"content": [{"type": "text"}], "stop_reason": "end_turn",
     "usage": {"input_tokens": 1, "output_tokens": 1}},
    [1, 2],
])
def test_missing_fields_anthropic(session, body):
    session(FakeResp(200, body=body))
    with pytest.raises(RemoteModelError):
        run()


@pytest.mark.parametrize("body", [
    {}, {"choices": []},
    {"choices": [{"message": {"content": "x"}}],
     "usage": {"prompt_tokens": 1, "completion_tokens": 1}},
    {"choices": [{"message": {"content": "x"}, "finish_reason": "stop"}]},
    {"choices": [{"message": {"content": 5}, "finish_reason": "stop"}],
     "usage": {"prompt_tokens": 1, "completion_tokens": 1}},
])
def test_missing_fields_openai(session, body):
    session(FakeResp(200, body=body))
    with pytest.raises(RemoteModelError):
        run(model=GROQ)


def test_redirect_is_error(session):
    calls = session(FakeResp(302, text="moved", headers={"location": "http://evil/"}))
    with pytest.raises(RemoteModelError, match="302"):
        run()
    assert len(calls) == 1


def test_local_name_is_refused():
    with pytest.raises(RemoteModelError, match="not a hosted model"):
        run(model="llama3.2:3b")


ERROR_CASES = [
    [FakeResp(400, text="bad")],
    [FakeResp(200, text="<html>")],
    [FakeResp(200, body={})],
    [FakeResp(302, text="m")],
    [FakeResp(429, text="s")] * 5,
    [requests.ConnectionError("down")] * 5,
]


@pytest.mark.parametrize("model", [ANTHROPIC, GROQ])
def test_key_never_in_error(session, caplog, model):
    for responses in ERROR_CASES:
        session(*responses)
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(RemoteModelError) as e:
                run(model=model)
        assert KEY not in str(e.value) and KEY not in repr(e.value)
    assert KEY not in caplog.text


def test_key_echoed_by_provider_is_scrubbed(session):
    session(FakeResp(401, text=f"invalid key {KEY}"))
    with pytest.raises(RemoteModelError) as e:
        run()
    assert KEY not in str(e.value)


def test_list_models(session):
    calls = session(FakeResp(body={"data": [{"id": "a"}, {"id": "b"}]}))
    assert list_models("groq", KEY) == ["a", "b"]
    c = calls[0]
    assert c["method"] == "get" and c["url"] == "https://api.groq.com/openai/v1/models"
    assert c["headers"]["Authorization"] == f"Bearer {KEY}" and c["allow_redirects"] is False


def test_list_models_anthropic_headers(session):
    calls = session(FakeResp(body={"data": [{"id": "claude-x"}]}))
    assert list_models("anthropic", KEY) == ["claude-x"]
    assert calls[0]["headers"]["x-api-key"] == KEY
    assert calls[0]["headers"]["anthropic-version"] == "2023-06-01"


def test_list_models_errors(session):
    with pytest.raises(RemoteModelError, match="unknown provider"):
        list_models("openai", KEY)
    session(FakeResp(body={"data": [{"nope": 1}]}))
    with pytest.raises(RemoteModelError):
        list_models("groq", KEY)
    session(FakeResp(401, text="denied"))
    with pytest.raises(RemoteModelError, match="401"):
        list_models("groq", KEY)


def test_malformed_key_never_leaks_through_real_header_validation(caplog):
    """No network: requests rejects the header while preparing the request."""
    import traceback
    bad = "sk-test-key\n"
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(RemoteModelError) as e:
            chat(ANTHROPIC, MSGS, temperature=None, seed=1, max_tokens=10, timeout_s=5,
                 api_key=bad, sleep=lambda s: pytest.fail("must not retry"))
    rendered = "".join(traceback.format_exception(e.value))
    assert "InvalidHeader" in str(e.value)
    assert "sk-test-key" not in rendered and "sk-test-key" not in caplog.text
    assert e.value.__cause__ is None and e.value.__context__ is None


def test_non_transport_request_error_is_not_retried(session):
    calls = session(requests.exceptions.InvalidURL("x"))
    sleeps = []
    with pytest.raises(RemoteModelError, match="InvalidURL"):
        run(sleeps=sleeps)
    assert sleeps == [] and len(calls) == 1


def test_connection_error_text_is_not_logged(session, caplog):
    session(requests.ConnectionError(f"boom {KEY}"), FakeResp(body=openai_body()))
    with caplog.at_level(logging.DEBUG):
        run(model=GROQ)
    assert KEY not in caplog.text and "ConnectionError" in caplog.text


def test_empty_assistant_turn_is_replaced_for_anthropic(session):
    calls = session(FakeResp(body=anthropic_body()))
    msgs = MSGS + [{"role": "assistant", "content": ""},
                   {"role": "user", "content": "fix"},
                   {"role": "assistant", "content": "  \n"},
                   {"role": "assistant", "content": "ok"}]
    chat(ANTHROPIC, msgs, temperature=None, seed=1, max_tokens=10, timeout_s=5,
         api_key=KEY, sleep=lambda s: None)
    out = calls[0]["json"]["messages"]
    assert [m["content"] for m in out] == [
        "hello", remote_client.EMPTY_REPLY_PLACEHOLDER, "fix",
        remote_client.EMPTY_REPLY_PLACEHOLDER, "ok"]
    assert remote_client.EMPTY_REPLY_PLACEHOLDER == "(empty reply)"
    assert msgs[2]["content"] == ""  # the caller's list is not mutated


def test_openai_messages_are_not_rewritten(session):
    calls = session(FakeResp(body=openai_body()))
    msgs = MSGS + [{"role": "assistant", "content": ""}]
    chat(GROQ, msgs, temperature=None, seed=1, max_tokens=10, timeout_s=5,
         api_key=KEY, sleep=lambda s: None)
    assert calls[0]["json"]["messages"] == msgs


def test_anthropic_without_system_message_omits_field(session):
    calls = session(FakeResp(body=anthropic_body()))
    chat(ANTHROPIC, MSGS[1:], temperature=None, seed=1, max_tokens=10, timeout_s=5,
         api_key=KEY, sleep=lambda s: None)
    assert "system" not in calls[0]["json"]


def test_list_models_retries_through_sleep(session):
    session(FakeResp(429, text="slow", headers={"retry-after": "2"}),
            FakeResp(body={"data": [{"id": "a"}]}))
    sleeps = []
    assert list_models("groq", KEY, sleep=sleeps.append) == ["a"]
    assert sleeps == [2]
