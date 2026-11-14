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


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), OSError("boom")])
def test_start_listener_stops_process_on_any_failure(monkeypatch, exc):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)

    def boom(base, p, wait_s):
        raise exc

    monkeypatch.setattr(listener_proc, "_wait_healthy", boom)
    try:
        with pytest.raises(type(exc)):
            listener_proc.start_listener("config.yaml", "x.db", "127.0.0.1", _free_port())
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


def test_start_listener_reports_early_exit(monkeypatch):
    proc = subprocess.Popen([sys.executable, "-c", "raise SystemExit(3)"])
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    with pytest.raises(RuntimeError, match="exited early with code 3"):
        listener_proc.start_listener("config.yaml", "x.db", "127.0.0.1", _free_port())


def test_start_listener_detects_foreign_health_answer(monkeypatch):
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    class DiesAfterFirstPoll:
        pid = 1
        returncode = 3
        polls = 0

        def poll(self):
            self.polls += 1
            return None if self.polls == 1 else 3

        def terminate(self):
            pass

        def wait(self, timeout):
            return 3

    proc = DiesAfterFirstPoll()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(listener_proc, "port_open", lambda h, p: False)
    try:
        with pytest.raises(RuntimeError, match="something"):
            listener_proc.start_listener("config.yaml", "x.db", "127.0.0.1", port)
    finally:
        srv.shutdown()
        srv.server_close()


def test_stop_listener_raises_when_kill_does_not_work():
    class Stubborn:
        pid = 4242

        def terminate(self):
            pass

        def kill(self):
            pass

        def wait(self, timeout):
            raise subprocess.TimeoutExpired("x", timeout)

    with pytest.raises(RuntimeError, match="4242"):
        listener_proc.stop_listener(Stubborn())


# ---- final fix wave: stop_listener reports a kill (F7) ----

def test_stop_listener_returns_false_after_clean_terminate():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    assert listener_proc.stop_listener(proc) is False


def test_stop_listener_returns_true_when_it_had_to_kill():
    class IgnoresTerminate:
        pid = 77
        killed = False

        def terminate(self):
            pass

        def kill(self):
            self.killed = True

        def wait(self, timeout):
            if not self.killed:
                raise subprocess.TimeoutExpired("x", timeout)
            return -9

    p = IgnoresTerminate()
    assert listener_proc.stop_listener(p) is True and p.killed
