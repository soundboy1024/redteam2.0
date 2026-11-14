import socket
import subprocess
import sys

import pytest

import listener_proc


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_port_open_false_for_free_port():
    assert listener_proc.port_open("127.0.0.1", _free_port()) is False


def test_port_open_true_for_bound_socket():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        assert listener_proc.port_open("127.0.0.1", s.getsockname()[1]) is True


def test_start_listener_raises_when_port_taken_and_launches_nothing(monkeypatch):
    launched = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: launched.append(a))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        with pytest.raises(RuntimeError, match=str(port)):
            listener_proc.start_listener("config.yaml", "x.db", "127.0.0.1", port)
    assert launched == []


def test_stop_listener_terminates_child():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    listener_proc.stop_listener(proc)
    assert proc.poll() is not None


def test_start_listener_stops_process_on_health_timeout(monkeypatch):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    try:
        with pytest.raises(RuntimeError, match="not healthy"):
            listener_proc.start_listener("config.yaml", "x.db", "127.0.0.1", _free_port(), wait_s=1)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
