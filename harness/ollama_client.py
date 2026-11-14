"""Raw-HTTP client for the local Ollama /api/chat endpoint. No SDK.

Must not import from traps/ or telemetry/. Every failure raises OllamaError.
"""
import urllib.parse
from dataclasses import dataclass

import requests

TOP_LOGPROBS = 20
_BODY_SNIPPET = 300
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost")

# Own session; trust_env=False so loopback traffic is never routed via a proxy.
_SESSION = requests.Session()
_SESSION.trust_env = False


class OllamaError(Exception):
    """Infrastructure failure talking to Ollama."""


@dataclass
class ChatResult:
    content: str
    logprobs: list[dict] | None
    token_count: int
    latency_ms: float
    tokens_per_sec: float | None
    done_reason: str


def _check_host(host: str) -> None:
    try:
        parts = urllib.parse.urlsplit(host)
        hostname = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError as e:
        raise OllamaError(f"refusing malformed ollama host {host!r}: {e}") from e
    if parts.scheme != "http" or hostname not in _LOOPBACK_HOSTS or parts.username or parts.password:
        raise OllamaError(f"refusing non-loopback ollama host {host!r}")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise OllamaError(f"refusing ollama host with path, query or fragment: {host!r}")


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _validate_logprobs(logprobs, raw: str) -> None:
    for i, e in enumerate(logprobs):
        problem = None
        if not isinstance(e, dict):
            problem = "entry is not an object"
        elif not isinstance(e.get("token"), str):
            problem = "missing string token"
        elif not _is_number(e.get("logprob")):
            problem = "missing numeric logprob"
        else:
            top = e.get("top_logprobs")
            if not isinstance(top, list) or not top:
                problem = "top_logprobs missing or empty"
            elif not all(isinstance(t, dict) and _is_number(t.get("logprob")) for t in top):
                problem = "top_logprobs entry lacks numeric logprob"
        if problem:
            raise OllamaError(f"malformed logprobs at index {i}: {problem}: {_snippet(raw)}")


def _snippet(text: str) -> str:
    return text[:_BODY_SNIPPET]


def chat(host: str, model: str, messages: list[dict], *, temperature: float, seed: int,
         num_ctx: int, num_predict: int, telemetry: bool, timeout_s: int) -> ChatResult:
    _check_host(host)
    body = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature, "seed": seed,
                    "num_ctx": num_ctx, "num_predict": num_predict},
    }
    if telemetry:
        body["logprobs"] = True
        body["top_logprobs"] = TOP_LOGPROBS
    url = host.rstrip("/") + "/api/chat"
    try:
        resp = _SESSION.post(url, json=body, timeout=timeout_s, allow_redirects=False)
    except requests.RequestException as e:
        raise OllamaError(f"request to {url} failed: {type(e).__name__}: {e}") from e
    if resp.status_code != 200:
        raise OllamaError(f"ollama returned HTTP {resp.status_code}: {_snippet(resp.text)}")
    try:
        data = resp.json()
    except ValueError as e:
        raise OllamaError(f"ollama response is not valid JSON: {_snippet(resp.text)}") from e
    message = data.get("message") if isinstance(data, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise OllamaError(f"ollama response lacks message.content string: {_snippet(resp.text)}")
    for field in ("eval_count", "eval_duration", "total_duration"):
        v = data.get(field)
        ok = isinstance(v, int) if field == "eval_count" else isinstance(v, (int, float))
        if isinstance(v, bool) or not ok:
            raise OllamaError(f"ollama response has bad timing field {field}={v!r}: "
                              f"{_snippet(resp.text)}")
    logprobs = None
    if telemetry:
        logprobs = data.get("logprobs")
        if not isinstance(logprobs, list) or not logprobs:
            raise OllamaError(f"telemetry on but response has no usable top-level logprobs: "
                              f"{_snippet(resp.text)}")
        _validate_logprobs(logprobs, resp.text)
    eval_duration = data["eval_duration"]
    tps = data["eval_count"] / (eval_duration / 1e9) if eval_duration else None
    return ChatResult(
        content=content,
        logprobs=logprobs,
        token_count=data["eval_count"],
        latency_ms=data["total_duration"] / 1e6,
        tokens_per_sec=tps,
        done_reason=str(data.get("done_reason", "")),
    )
