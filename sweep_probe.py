"""Model sweep: every call to Ollama and to the operating system (CLAUDE.md 4.9).

Raw HTTP to the local Ollama server, no SDK. Nothing here imports harness/, traps/ or
telemetry/.
"""
import ctypes
import logging
import os
import re
import shutil
import time

import requests

log = logging.getLogger(__name__)
DEFAULT_LOG = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Ollama", "server.log")
SHORT_TIMEOUT_S = 30


class ProbeError(RuntimeError):
    pass


def _session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    return s


def _call(method: str, host: str, endpoint: str, body: dict | None = None,
          timeout_s: float = SHORT_TIMEOUT_S, want_json: bool = True):
    session = _session()
    try:
        try:
            resp = session.request(method, host + endpoint, json=body, timeout=timeout_s)
        except requests.RequestException as exc:
            raise ProbeError(f"{method} {endpoint} failed: {type(exc).__name__}: {exc}") from exc
        if resp.status_code != 200:
            raise ProbeError(f"{method} {endpoint} returned HTTP {resp.status_code}: "
                             f"{resp.text[:300]}")
        if not want_json:
            return None
        try:
            data = resp.json()
        except ValueError as exc:
            raise ProbeError(f"{method} {endpoint} did not return JSON: "
                             f"{resp.text[:300]}") from exc
        if not isinstance(data, dict):
            raise ProbeError(f"{method} {endpoint} returned JSON that is not an object")
        if data.get("error"):
            raise ProbeError(f"{method} {endpoint} returned an error: {data['error']}")
        return data
    finally:
        session.close()


def _models(data: dict, endpoint: str) -> list:
    models = data.get("models")
    if not isinstance(models, list):
        raise ProbeError(f"GET {endpoint} returned no models list")
    return models


def installed(host: str) -> dict[str, dict]:
    data = _call("GET", host, "/api/tags")
    return {m["name"]: {"digest": m.get("digest"), "size": m.get("size")}
            for m in _models(data, "/api/tags")}


def is_installed(tag: str, names) -> bool:
    if tag in names:
        return True
    if ":" not in tag:
        return tag + ":latest" in names
    if tag.endswith(":latest"):
        return tag[:-len(":latest")] in names
    return False


def loaded(host: str) -> list[dict]:
    data = _call("GET", host, "/api/ps")
    return [{"name": m["name"], "size": m.get("size"), "size_vram": m.get("size_vram")}
            for m in _models(data, "/api/ps")]


def pull(host: str, tag: str, timeout_s: float = 7200) -> None:
    data = _call("POST", host, "/api/pull", {"model": tag, "stream": False}, timeout_s)
    if data.get("status") != "success":
        raise ProbeError(f"POST /api/pull for {tag} did not end with status success: "
                         f"{str(data)[:300]}")


def load_check(host: str, tag: str, num_ctx: int, timeout_s: float = 600) -> dict:
    data = _call("POST", host, "/api/chat", {
        "model": tag, "stream": False,
        "messages": [{"role": "user", "content": "Reply with the word ok."}],
        "options": {"num_ctx": num_ctx, "num_predict": 16}}, timeout_s)
    count, duration = data.get("eval_count"), data.get("eval_duration")
    speed = count / (duration / 1e9) if count and duration else None
    return {"tokens_per_s": speed}


def unload(host: str, tag: str, wait_s: float = 120, sleep=time.sleep) -> bool:
    """Ask Ollama to unload the model, then wait until it is gone. False if it stays."""
    _call("POST", host, "/api/generate", {"model": tag, "keep_alive": 0}, 120)
    waited = 0.0
    while True:
        names = {m["name"] for m in loaded(host)}
        if not is_installed(tag, names):
            return True
        if waited >= wait_s:
            return False
        sleep(2)
        waited += 2


def delete(host: str, tag: str) -> None:
    _call("DELETE", host, "/api/delete", {"model": tag}, 120, want_json=False)


class _MemoryStatus(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def free_memory_bytes() -> int:
    """Free physical memory (Windows GlobalMemoryStatusEx)."""
    status = _MemoryStatus()
    status.dwLength = ctypes.sizeof(_MemoryStatus)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ProbeError(f"GlobalMemoryStatusEx failed: error {ctypes.get_last_error()}")
    return int(status.ullAvailPhys)


def free_disk_bytes(path: str) -> int:
    return shutil.disk_usage(path).free


def log_size(log_path: str) -> int:
    return os.path.getsize(log_path) if os.path.exists(log_path) else 0


def backend_from_log(log_path: str, since_offset: int) -> str | None:
    """The last GPU library Ollama's log names after since_offset (Vulkan, ROCm, cpu...)."""
    if not os.path.exists(log_path):
        log.warning("Ollama log %s not found; backend not recorded", log_path)
        return None
    with open(log_path, "rb") as f:
        if since_offset <= os.path.getsize(log_path):
            f.seek(since_offset)
        text = f.read().decode("utf-8", errors="replace")
    found = re.findall(r"\blibrary=(\w+)", text)
    if not found:
        log.warning("no 'library=' line in %s after offset %s; backend not recorded",
                    log_path, since_offset)
        return None
    return found[-1]
