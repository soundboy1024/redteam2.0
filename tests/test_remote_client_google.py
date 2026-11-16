"""The Google (Gemini) hosted client, CLAUDE.md 4.7."""
import logging

import pytest
import requests

from harness import remote_client
from harness.remote_client import (PROVIDERS, RemoteModelError, accepts_temperature, chat,
                                   list_models, split_model)
from test_remote_client import KEY, MSGS, FakeResp, session  # noqa: F401

GOOGLE = "google/gemini-4-argon"
CHAT_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-4-argon:generateContent"


def google_body(parts=None, finish="STOP", **over):
    b = {"candidates": [{"content": {"role": "model",
                                     "parts": [{"text": '{"final": "x"}'}] if parts is None
                                     else parts},
                         "finishReason": finish}],
         "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 6}}
    b.update(over)
    return b


def run(messages=MSGS, temperature=None, model=GOOGLE):
    return chat(model, messages, temperature=temperature, seed=3, max_tokens=4096,
                timeout_s=30, api_key=KEY, sleep=lambda s: None)


def test_google_provider_constants():
    assert PROVIDERS["google"] == {
        "chat_url": "https://generativelanguage.googleapis.com/v1beta/models/{model}"
                    ":generateContent",
        "models_url": "https://generativelanguage.googleapis.com/v1beta/models",
        "key_env": "GOOGLE_API_KEY"}
    assert split_model(GOOGLE) == ("google", "gemini-4-argon")
    assert accepts_temperature(GOOGLE) is True


def test_google_request_shape(session):
    calls = session(FakeResp(body=google_body()))
    messages = MSGS + [{"role": "assistant", "content": "A1"}, {"role": "user", "content": "U2"}]
    result = run(messages)
    c = calls[0]
    assert c["method"] == "post" and c["url"] == CHAT_URL
    assert c["headers"]["x-goog-api-key"] == KEY and "Authorization" not in c["headers"]
    assert KEY not in c["url"] and "params" not in c and c["allow_redirects"] is False
    assert c["json"] == {
        "systemInstruction": {"parts": [{"text": "SYS"}]},
        "contents": [{"role": "user", "parts": [{"text": "hello"}]},
                     {"role": "model", "parts": [{"text": "A1"}]},
                     {"role": "user", "parts": [{"text": "U2"}]}],
        "generationConfig": {"maxOutputTokens": 4096, "seed": 3}}
    assert result.content == '{"final": "x"}' and result.done_reason == "stop"
    assert result.token_count == 6 and result.prompt_token_count == 12
    assert result.logprobs is None


def test_google_temperature_sent_only_when_given(session):
    calls = session(FakeResp(body=google_body()))
    run(temperature=0.3)
    assert calls[0]["json"]["generationConfig"]["temperature"] == 0.3


def test_google_without_system_message_omits_the_field(session):
    calls = session(FakeResp(body=google_body()))
    run([{"role": "user", "content": "hello"}])
    assert "systemInstruction" not in calls[0]["json"]


def test_google_reply_joins_text_and_skips_thought_parts(session):
    session(FakeResp(body=google_body(
        parts=[{"text": "thinking...", "thought": True}, {"text": '{"final": '},
               {"text": '"y"}'}, {"inlineData": {"mimeType": "x", "data": ""}}],
        usageMetadata={"promptTokenCount": 12, "candidatesTokenCount": 6,
                       "thoughtsTokenCount": 30})))
    result = run()
    assert result.content == '{"final": "y"}'
    assert result.token_count == 36       # thinking counts as output, as it does for Claude


@pytest.mark.parametrize("finish,expected", [("STOP", "stop"), ("MAX_TOKENS", "length"),
                                             ("SAFETY", "safety"),
                                             ("PROHIBITED_CONTENT", "prohibited_content")])
def test_google_done_reason(session, finish, expected):
    session(FakeResp(body=google_body(finish=finish)))
    assert run().done_reason == expected


def test_google_candidate_without_content_is_an_empty_reply(session):
    session(FakeResp(body={"candidates": [{"finishReason": "SAFETY"}],
                           "usageMetadata": {"promptTokenCount": 12}}))
    result = run()
    assert result.content == "" and result.done_reason == "safety" and result.token_count == 0


def test_google_blocked_prompt_is_an_empty_reply_not_an_error(session):
    session(FakeResp(body={"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"},
                           "usageMetadata": {"promptTokenCount": 12}}))
    result = run()
    assert result.content == "" and result.done_reason == "blocked:prohibited_content"
    assert result.token_count == 0 and result.prompt_token_count == 12


def test_google_blocked_prompt_without_a_prompt_token_count(session):
    # Seen live on 2026-11-15: a blocked prompt reports no token counts at all.
    session(FakeResp(body={"promptFeedback": {"blockReason": "OTHER"},
                           "usageMetadata": {"serviceTier": "standard"},
                           "modelVersion": "gemini-4-carbon"}))
    result = run()
    assert result.content == "" and result.done_reason == "blocked:other"
    assert result.token_count == 0 and result.prompt_token_count is None


def test_google_blocked_prompt_without_usage_metadata(session):
    session(FakeResp(body={"promptFeedback": {"blockReason": "OTHER"}}))
    result = run()
    assert result.done_reason == "blocked:other" and result.prompt_token_count is None


@pytest.mark.parametrize("body", [
    [],
    {},
    {"candidates": [], "usageMetadata": {"promptTokenCount": 1}},
    {"candidates": [{"content": {"parts": [{"text": "x"}]}}],
     "usageMetadata": {"promptTokenCount": 1}},
    {"candidates": [{"content": {"parts": "x"}, "finishReason": "STOP"}],
     "usageMetadata": {"promptTokenCount": 1}},
    {"candidates": [{"content": {"parts": [{"text": 5}]}, "finishReason": "STOP"}],
     "usageMetadata": {"promptTokenCount": 1}},
    {"candidates": [{"content": {"parts": [{"text": "x"}]}, "finishReason": "STOP"}]},
    {"candidates": [{"content": {"parts": [{"text": "x"}]}, "finishReason": "STOP"}],
     "usageMetadata": {"promptTokenCount": "many"}},
    {"promptFeedback": {}, "usageMetadata": {"promptTokenCount": 1}},
])
def test_google_missing_fields(session, body):
    session(FakeResp(body=body))
    with pytest.raises(RemoteModelError):
        run()


def test_google_empty_assistant_turn_is_replaced(session):
    calls = session(FakeResp(body=google_body()))
    run(MSGS + [{"role": "assistant", "content": "  "}, {"role": "user", "content": "again"}])
    assert calls[0]["json"]["contents"][1] == {
        "role": "model", "parts": [{"text": remote_client.EMPTY_REPLY_PLACEHOLDER}]}


@pytest.mark.parametrize("model_id", ["a/b", "x?key=1", "..", "a b", "", "x:generateContent"])
def test_google_model_id_that_could_change_the_url_is_refused(session, model_id):
    calls = session(FakeResp(body=google_body()))
    with pytest.raises(RemoteModelError, match="model id"):
        run(model="google/" + model_id)
    assert calls == []


def test_google_key_never_in_error_or_log(session, caplog):
    cases = [[FakeResp(401, text="bad key " + KEY)], [FakeResp(200, text="<html>")],
             [FakeResp(200, body={})], [FakeResp(302, text="m")],
             [FakeResp(429, text="s")] * 5, [requests.ConnectionError("down " + KEY)] * 5]
    for responses in cases:
        session(*responses)
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(RemoteModelError) as e:
                run()
        assert KEY not in str(e.value) and KEY not in repr(e.value)
    assert KEY not in caplog.text


def test_google_list_models(session):
    calls = session(FakeResp(body={"models": [{"name": "models/gemini-4-argon"},
                                              {"name": "models/gemini-3.8-flash"}]}))
    assert list_models("google", KEY) == ["gemini-4-argon", "gemini-3.8-flash"]
    c = calls[0]
    assert c["method"] == "get" and c["url"] == PROVIDERS["google"]["models_url"]
    assert c["headers"]["x-goog-api-key"] == KEY and c["params"] == {"pageSize": 1000}
    session(FakeResp(body={"models": [{"id": "x"}]}))
    with pytest.raises(RemoteModelError):
        list_models("google", KEY)
