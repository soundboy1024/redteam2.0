"""Start and stop the decoy listener as a subprocess (launched by module name)."""
import logging
import os
import socket
import subprocess
import sys
import time

import requests

log = logging.getLogger(__name__)
ROOT = os.path.dirname(os.path.abspath(__file__))


def port_open(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


def stop_listener(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        log.warning("listener ignored terminate; killing the process this run started")
        proc.kill()
        proc.wait(timeout=10)


def _wait_healthy(base: str, proc: subprocess.Popen, wait_s: int) -> None:
    session = requests.Session()
    session.trust_env = False
    deadline = time.time() + wait_s
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"listener exited early with code {proc.returncode}")
        try:
            if session.get(base + "/health", timeout=1).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"listener not healthy after {wait_s}s")


def start_listener(config_path: str, db_path: str, host: str, port: int,
                   wait_s: int = 15) -> subprocess.Popen:
    if port_open(host, port):
        raise RuntimeError(f"port {port} already in use; not touching it")
    proc = subprocess.Popen(
        [sys.executable, "-m", "traps.honeypot_server", "--config", config_path,
         "--db", db_path, "--port", str(port)],
        cwd=ROOT)
    try:
        _wait_healthy(f"http://{host}:{port}", proc, wait_s)
    except RuntimeError:
        log.error("listener on port %s failed to start; stopping it", port)
        stop_listener(proc)
        raise
    return proc
