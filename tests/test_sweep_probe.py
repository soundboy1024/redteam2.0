import pytest
import requests

import sweep_probe as sp

HOST = "http://127.0.0.1:11434"


class FakeResponse:
    def __init__(self, status=200, body=None, text=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else str(body)

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    """Answers from a list, in order; the last answer repeats. Records every call."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def request(self, method, url, json=None, timeout=None):
        self.calls.append((method, url, json))
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    def close(self):
        pass


@pytest.fixture
def fake(monkeypatch):
    def install(*answers):
        session = FakeSession(answers)
        monkeypatch.setattr(sp, "_session", lambda: session)
        return session
    return install


def test_installed_and_loaded_parse_ollama_shapes(fake):
    fake(FakeResponse(body={"models": [{"name": "a:1b", "digest": "d1", "size": 10}]}))
    assert sp.installed(HOST) == {"a:1b": {"digest": "d1", "size": 10}}
    s = fake(FakeResponse(body={"models": [{"name": "a:1b", "size": 8, "size_vram": 6,
                                            "extra": 1}]}))
    assert sp.loaded(HOST) == [{"name": "a:1b", "size": 8, "size_vram": 6}]
    assert s.calls == [("GET", HOST + "/api/ps", None)]


@pytest.mark.parametrize("tag,names,expected", [
    ("llama3.2", {"llama3.2:latest"}, True),
    ("llama3.2:latest", {"llama3.2"}, True),
    ("llama3.2:1b", {"llama3.2:latest"}, False),
    ("a:1b", {"a:1b", "b:1b"}, True),
    ("a:1b", set(), False),
])
def test_is_installed(tag, names, expected):
    assert sp.is_installed(tag, names) is expected


def test_pull_succeeds_only_on_status_success(fake):
    s = fake(FakeResponse(body={"status": "success"}))
    sp.pull(HOST, "a:1b")
    assert s.calls == [("POST", HOST + "/api/pull", {"model": "a:1b", "stream": False})]
    for answer, needle in [(FakeResponse(status=404, body={"error": "file does not exist"}),
                            "404"),
                           (FakeResponse(body={"error": "pull model manifest: not found"}),
                            "not found"),
                           (FakeResponse(body={"status": "pulling"}), "success"),
                           (FakeResponse(body=None, text="<html>"), "JSON")]:
        fake(answer)
        with pytest.raises(sp.ProbeError, match=needle) as exc:
            sp.pull(HOST, "a:1b")
        assert "/api/pull" in str(exc.value)


def test_load_check_tokens_per_second(fake):
    s = fake(FakeResponse(body={"message": {"content": "ok"}, "eval_count": 40,
                                "eval_duration": 2_000_000_000}))
    assert sp.load_check(HOST, "a:1b", 8192) == {"tokens_per_s": 20.0}
    sent = s.calls[0][2]
    assert sent["options"] == {"num_ctx": 8192, "num_predict": 16} and sent["stream"] is False
    fake(FakeResponse(body={"message": {"content": "ok"}, "eval_count": 40,
                            "eval_duration": 0}))
    assert sp.load_check(HOST, "a:1b", 8192) == {"tokens_per_s": None}
    fake(FakeResponse(status=500, body={"error": "model requires more system memory"}))
    with pytest.raises(sp.ProbeError, match="more system memory"):
        sp.load_check(HOST, "a:1b", 8192)


def test_unload_waits_until_the_model_is_gone(fake):
    still = FakeResponse(body={"models": [{"name": "a:1b", "size": 1, "size_vram": 1}]})
    gone = FakeResponse(body={"models": []})
    s = fake(FakeResponse(body={"done": True}), still, gone)
    assert sp.unload(HOST, "a:1b", sleep=lambda _: None) is True
    assert s.calls[0] == ("POST", HOST + "/api/generate", {"model": "a:1b", "keep_alive": 0})
    fake(FakeResponse(body={"done": True}), still)
    assert sp.unload(HOST, "a:1b", wait_s=6, sleep=lambda _: None) is False


def test_delete_sends_the_tag(fake):
    s = fake(FakeResponse(body=None, text=""))
    sp.delete(HOST, "a:1b")
    assert s.calls == [("DELETE", HOST + "/api/delete", {"model": "a:1b"})]
    fake(FakeResponse(status=404, body={"error": "model not found"}))
    with pytest.raises(sp.ProbeError, match="404"):
        sp.delete(HOST, "a:1b")


def test_connection_error_names_the_endpoint(fake):
    fake(requests.ConnectionError("refused"))
    with pytest.raises(sp.ProbeError, match="/api/tags"):
        sp.installed(HOST)
    fake(requests.Timeout("slow"))
    with pytest.raises(sp.ProbeError, match="/api/ps"):
        sp.loaded(HOST)


def test_backend_from_log(tmp_path):
    log = tmp_path / "server.log"
    first = b'msg="selecting GPU backend" library=ROCm\n'
    second = b'msg="selecting GPU backend" library=Vulkan variant=x\nother\n'
    log.write_bytes(first + second)
    assert sp.log_size(str(log)) == len(first) + len(second)
    assert sp.backend_from_log(str(log), 0) == "Vulkan"
    assert sp.backend_from_log(str(log), len(first)) == "Vulkan"
    assert sp.backend_from_log(str(log), len(first) + len(second)) is None
    log.write_bytes(first)
    assert sp.backend_from_log(str(log), 0) == "ROCm"
    assert sp.backend_from_log(str(tmp_path / "missing.log"), 0) is None
    assert sp.log_size(str(tmp_path / "missing.log")) == 0
    # the log was rotated and is now shorter than the remembered offset: read it all
    assert sp.backend_from_log(str(log), 10_000) == "ROCm"


def test_real_memory_and_disk_probes():
    assert sp.free_memory_bytes() > 0
    assert sp.free_disk_bytes(".") > 0
