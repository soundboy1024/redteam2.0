"""Raw-HTTP clients for hosted models (Anthropic, Groq, Cerebras). No SDK.

Must not import from traps/ or telemetry/. Every failure raises RemoteModelError.
The API key is an argument; it is never logged and never put in an exception.
Endpoints are fixed constants below; nothing about them is configurable.
"""
import logging
import time

import requests

from harness.ollama_client import ChatResult, ModelError

log = logging.getLogger(__name__)

PROVIDERS = {
    "anthropic": {"chat_url": "https://api.anthropic.com/v1/messages",
                  "models_url": "https://api.anthropic.com/v1/models",
                  "key_env": "ANTHROPIC_API_KEY"},
    "groq": {"chat_url": "https://api.groq.com/openai/v1/chat/completions",
             "models_url": "https://api.groq.com/openai/v1/models",
             "key_env": "GROQ_API_KEY"},
    "cerebras": {"chat_url": "https://api.cerebras.ai/v1/chat/completions",
                 "models_url": "https://api.cerebras.ai/v1/models",
                 "key_env": "CEREBRAS_API_KEY"},
}
ANTHROPIC_TEMPERATURE_MODELS = ("claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-6")
ANTHROPIC_VERSION = "2023-06-01"
MAX_ATTEMPTS = 5
RETRY_STATUSES = (429, 500, 502, 503, 529)
BACKOFF_S = (2, 4, 8, 16)
RETRY_AFTER_CAP_S = 60
_BODY_SNIPPET = 300
EMPTY_REPLY_PLACEHOLDER = "(empty reply)"
_STOP_REASONS = {"end_turn": "stop", "stop_sequence": "stop", "max_tokens": "length"}

# Own session; trust_env=False so traffic never goes via an environment proxy.
_SESSION = requests.Session()
_SESSION.trust_env = False


class RemoteModelError(ModelError):
    """Infrastructure failure talking to a hosted model provider."""


def split_model(name: str) -> tuple[str | None, str]:
    """'anthropic/x' to ('anthropic', 'x'); any other name is local: (None, name)."""
    prefix, sep, rest = name.partition("/")
    if sep and prefix in PROVIDERS:
        return prefix, rest
    return None, name


def accepts_temperature(name: str) -> bool:
    provider, model_id = split_model(name)
    if provider == "anthropic":
        return model_id in ANTHROPIC_TEMPERATURE_MODELS
    return True


def _is_count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _headers(provider: str, api_key: str) -> dict:
    if provider == "anthropic":
        return {"x-api-key": api_key, "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json"}
    return {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}


def _scrub(text: str, api_key: str) -> str:
    return text.replace(api_key, "[key]") if api_key else text


def _snippet(text: str, api_key: str) -> str:
    return _scrub(text, api_key)[:_BODY_SNIPPET]


def _wait_seconds(resp, attempt: int) -> float:
    """retry-after capped at 60 s when numeric, else 2, 4, 8, 16."""
    raw = resp.headers.get("retry-after") if resp is not None else None
    if raw is not None:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = None
        if value is not None and value >= 0:
            wait = min(value, RETRY_AFTER_CAP_S)
            return int(wait) if wait == int(wait) else wait
    return BACKOFF_S[attempt]


def _send(method: str, provider: str, url: str, api_key: str, timeout_s: int, sleep,
          *, body: dict | None = None, params: dict | None = None):
    """One request with bounded retry. Returns (response, wall seconds of the
    successful attempt). Raises RemoteModelError for anything else."""
    kwargs = {"headers": _headers(provider, api_key), "timeout": timeout_s,
              "allow_redirects": False}
    if body is not None:
        kwargs["json"] = body
    if params is not None:
        kwargs["params"] = params
    send = _SESSION.post if method == "post" else _SESSION.get
    for attempt in range(MAX_ATTEMPTS):
        start = time.perf_counter()
        fatal = None
        try:
            resp = send(url, **kwargs)
            elapsed = time.perf_counter() - start
            problem, retry_resp = None, resp
        except (requests.ConnectionError, requests.Timeout) as e:
            # Type name only: str(e) is never logged or raised, so a header value
            # (the key) that an exception message might carry cannot leak.
            resp, elapsed, retry_resp = None, 0.0, None
            problem = type(e).__name__
        except requests.RequestException as e:
            fatal = type(e).__name__
        if fatal is not None:  # raised outside the except block: no chained exception text
            raise RemoteModelError(f"{provider} request could not be sent: {fatal}")
        if resp is not None:
            if resp.status_code == 200:
                return resp, elapsed
            if resp.status_code not in RETRY_STATUSES:
                raise RemoteModelError(
                    f"{provider} returned HTTP {resp.status_code}: "
                    f"{_snippet(resp.text, api_key)}")
            problem = f"HTTP {resp.status_code}"
        if attempt == MAX_ATTEMPTS - 1:
            detail = _snippet(resp.text, api_key) if resp is not None else problem
            raise RemoteModelError(
                f"{provider} failed after {MAX_ATTEMPTS} attempts: {problem}: {detail}")
        wait = _wait_seconds(retry_resp, attempt)
        log.warning("%s request failed (%s); retry %d of %d in %s s",
                    provider, problem, attempt + 1, MAX_ATTEMPTS - 1, wait)
        sleep(wait)
    raise AssertionError("unreachable")  # pragma: no cover


def _json(resp, provider: str, api_key: str):
    try:
        return resp.json()
    except ValueError as e:
        raise RemoteModelError(f"{provider} response is not valid JSON: "
                               f"{_snippet(resp.text, api_key)}") from e


def _bad(provider: str, what: str, resp, api_key: str) -> RemoteModelError:
    return RemoteModelError(f"{provider} response {what}: {_snippet(resp.text, api_key)}")


def _anthropic_reply(data, resp, api_key: str) -> tuple[str, str, int, int]:
    p = "anthropic"
    if not isinstance(data, dict):
        raise _bad(p, "is not a JSON object", resp, api_key)
    blocks, stop, usage = data.get("content"), data.get("stop_reason"), data.get("usage")
    if not isinstance(blocks, list):
        raise _bad(p, "lacks a content list", resp, api_key)
    if not isinstance(stop, str):
        raise _bad(p, "lacks a stop_reason string", resp, api_key)
    if (not isinstance(usage, dict) or not _is_count(usage.get("input_tokens"))
            or not _is_count(usage.get("output_tokens"))):
        raise _bad(p, "lacks usage input_tokens and output_tokens", resp, api_key)
    texts = []
    for b in blocks:
        if not isinstance(b, dict):
            raise _bad(p, "has a content block that is not an object", resp, api_key)
        if b.get("type") == "text":
            if not isinstance(b.get("text"), str):
                raise _bad(p, "has a text block without a text string", resp, api_key)
            texts.append(b["text"])
    return ("".join(texts), _STOP_REASONS.get(stop, stop),
            usage["output_tokens"], usage["input_tokens"])


def _openai_reply(data, resp, provider: str, api_key: str) -> tuple[str, str, int, int]:
    if not isinstance(data, dict):
        raise _bad(provider, "is not a JSON object", resp, api_key)
    choices, usage = data.get("choices"), data.get("usage")
    first = choices[0] if isinstance(choices, list) and choices else None
    message = first.get("message") if isinstance(first, dict) else None
    if not isinstance(message, dict):
        raise _bad(provider, "lacks choices[0].message", resp, api_key)
    content, finish = message.get("content"), first.get("finish_reason")
    if content is not None and not isinstance(content, str):
        raise _bad(provider, "has non-string message content", resp, api_key)
    if not isinstance(finish, str):
        raise _bad(provider, "lacks a finish_reason string", resp, api_key)
    if (not isinstance(usage, dict) or not _is_count(usage.get("completion_tokens"))
            or not _is_count(usage.get("prompt_tokens"))):
        raise _bad(provider, "lacks usage prompt_tokens and completion_tokens", resp, api_key)
    return (content or "", finish, usage["completion_tokens"], usage["prompt_tokens"])


def chat(model_name: str, messages: list[dict], *, temperature: float | None, seed: int,
         max_tokens: int, timeout_s: int, api_key: str, sleep=time.sleep) -> ChatResult:
    provider, model_id = split_model(model_name)
    if provider is None:
        raise RemoteModelError(f"{model_name!r} is not a hosted model name")
    if provider == "anthropic":
        rest = list(messages)
        body = {"model": model_id, "max_tokens": max_tokens}
        if rest and rest[0].get("role") == "system":
            body["system"], rest = rest[0]["content"], rest[1:]
        # The API rejects empty assistant text; the run log keeps the true empty reply.
        body["messages"] = [
            {**m, "content": EMPTY_REPLY_PLACEHOLDER}
            if m.get("role") == "assistant" and not str(m.get("content", "")).strip() else m
            for m in rest]
    else:
        body = {"model": model_id, "messages": messages, "max_tokens": max_tokens,
                "seed": seed, "stream": False}
    if temperature is not None:
        body["temperature"] = temperature
    resp, elapsed = _send("post", provider, PROVIDERS[provider]["chat_url"], api_key,
                          timeout_s, sleep, body=body)
    data = _json(resp, provider, api_key)
    if provider == "anthropic":
        content, done, tokens, prompt_tokens = _anthropic_reply(data, resp, api_key)
    else:
        content, done, tokens, prompt_tokens = _openai_reply(data, resp, provider, api_key)
    return ChatResult(
        content=content, logprobs=None, token_count=tokens, latency_ms=elapsed * 1000.0,
        tokens_per_sec=tokens / elapsed if tokens and elapsed else None,
        done_reason=done, prompt_token_count=prompt_tokens)


def list_models(provider: str, api_key: str, timeout_s: int = 30,
                sleep=time.sleep) -> list[str]:
    if provider not in PROVIDERS:
        raise RemoteModelError(f"unknown provider {provider!r}; known: {sorted(PROVIDERS)}")
    params = {"limit": 1000} if provider == "anthropic" else None
    resp, _ = _send("get", provider, PROVIDERS[provider]["models_url"], api_key, timeout_s,
                    sleep, params=params)
    data = _json(resp, provider, api_key)
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list) or not all(
            isinstance(i, dict) and isinstance(i.get("id"), str) for i in items):
        raise _bad(provider, "lacks a data list of objects with string ids", resp, api_key)
    return [i["id"] for i in items]
