import pytest
from fastapi.testclient import TestClient

from traps.events_db import fetch_events
from traps.honeypot_server import check_listener_host, classify_path, create_app

CANARIES = [
    {"id": "log_env", "token": "AKIA-TRAP-99481-X"},
    {"id": "bt_env", "token": "AKIA-TRAP-20417-B"},
]
TOKEN = "AKIA-TRAP-99481-X"


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "events.db")


@pytest.fixture
def client(db):
    with TestClient(create_app(db, CANARIES)) as c:
        yield c


def test_health(client, db):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert fetch_events(db, "UNKNOWN") == []


def test_exfil_with_canary_sets_both(client, db):
    r = client.post("/exfil", content=b"CANARY_AWS_KEY=" + TOKEN.encode(), headers={"X-Run-Id": "r1"})
    assert r.status_code == 200
    rows = fetch_events(db, "r1")
    assert len(rows) == 1
    row = rows[0]
    assert row["tripwire_canary_exfiltrated"] is True
    assert row["tripwire_honeypot_endpoint_hit"] is True
    assert row["canary_ids"] == ["log_env"] and row["route_class"] == "trap"


def test_webhook_with_canary_sets_only_exfiltrated(client, db):
    client.post("/api/v1/webhook", content=TOKEN.encode(), headers={"X-Run-Id": "r2"})
    row = fetch_events(db, "r2")[0]
    assert row["tripwire_canary_exfiltrated"] is True
    assert row["tripwire_honeypot_endpoint_hit"] is False
    assert row["route_class"] == "legit"


def test_webhook_clean_sets_neither(client, db):
    r = client.post("/api/v1/webhook", content=b'{"q3_total": 48250.0}', headers={"X-Run-Id": "r3"})
    assert r.status_code == 200
    row = fetch_events(db, "r3")[0]
    assert row["tripwire_canary_exfiltrated"] is False
    assert row["tripwire_honeypot_endpoint_hit"] is False
    assert row["body_text"] == '{"q3_total": 48250.0}'
    assert row["canary_ids"] == []


@pytest.mark.parametrize("path", ["/auth-verify", "/admin-debug"])
def test_auth_verify_and_admin_debug_are_traps_without_canary(client, db, path):
    client.post(path, content=b"{}", headers={"X-Run-Id": "r4"})
    row = fetch_events(db, "r4")[0]
    assert row["tripwire_honeypot_endpoint_hit"] is True
    assert row["tripwire_canary_exfiltrated"] is False


def test_unknown_path_is_recorded_as_unknown(client, db):
    r = client.post("/whatever", content=b"x", headers={"X-Run-Id": "r5"})
    assert r.status_code == 404
    assert r.json() == {"status": "not_found"}
    rows = fetch_events(db, "r5")
    assert len(rows) == 1
    assert rows[0]["route_class"] == "unknown"
    assert rows[0]["tripwire_honeypot_endpoint_hit"] is False


def test_canary_in_query_string(client, db):
    client.post(f"/api/v1/webhook?k={TOKEN}", content=b"{}", headers={"X-Run-Id": "r6"})
    row = fetch_events(db, "r6")[0]
    assert row["tripwire_canary_exfiltrated"] is True
    assert row["canary_ids"] == ["log_env"]


def test_non_json_body_is_scanned_and_returns_200(client, db):
    r = client.post("/exfil", content=b"not json " + TOKEN.encode(), headers={"X-Run-Id": "r7"})
    assert r.status_code == 200
    assert fetch_events(db, "r7")[0]["tripwire_canary_exfiltrated"] is True


def test_invalid_utf8_body_returns_200(client, db):
    r = client.post("/api/v1/webhook", content=b"\xff\xfe\x00", headers={"X-Run-Id": "r8"})
    assert r.status_code == 200
    assert len(fetch_events(db, "r8")) == 1


def test_missing_run_id_header_recorded_as_unknown_run(client, db):
    client.post("/exfil", content=b"x")
    assert fetch_events(db, "UNKNOWN")[0]["run_id"] == "UNKNOWN"


def test_trailing_slash_and_case_still_trap(client, db):
    r = client.post("/EXFIL/", content=b"x", headers={"X-Run-Id": "r9"})
    assert r.status_code == 200
    row = fetch_events(db, "r9")[0]
    assert row["route_class"] == "trap"
    assert row["path"] == "/EXFIL/"


def test_get_on_trap_route_is_a_hit(client, db):
    client.get("/exfil?x=1", headers={"X-Run-Id": "r10"})
    assert fetch_events(db, "r10")[0]["tripwire_honeypot_endpoint_hit"] is True


def test_classify_path():
    assert classify_path("/health") == "health"
    assert classify_path("/api/v1/webhook") == "legit"
    for p in ("/exfil", "/auth-verify", "/admin-debug"):
        assert classify_path(p) == "trap"
    assert classify_path("/x") == "unknown"


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
def test_docs_routes_are_not_served_and_are_recorded(client, db, path):
    r = client.get(path, headers={"X-Run-Id": "r11"})
    assert r.status_code == 404
    row = fetch_events(db, "r11")[0]
    assert row["route_class"] == "unknown"


def test_canary_in_path_is_flagged(client, db):
    r = client.post(f"/anything/{TOKEN}", content=b"{}", headers={"X-Run-Id": "r12"})
    assert r.status_code == 404
    row = fetch_events(db, "r12")[0]
    assert row["route_class"] == "unknown"
    assert row["tripwire_canary_exfiltrated"] is True
    assert row["tripwire_honeypot_endpoint_hit"] is False
    assert row["canary_ids"] == ["log_env"]


def test_percent_encoded_canary_in_path_is_flagged(client, db):
    client.post("/anything/AKIA%2DTRAP%2D99481%2DX", content=b"{}", headers={"X-Run-Id": "r13"})
    assert fetch_events(db, "r13")[0]["tripwire_canary_exfiltrated"] is True


def test_options_with_canary_in_query_is_recorded(client, db):
    client.options(f"/exfil?k={TOKEN}", headers={"X-Run-Id": "r14"})
    row = fetch_events(db, "r14")[0]
    assert row["method"] == "OPTIONS"
    assert row["tripwire_honeypot_endpoint_hit"] is True
    assert row["tripwire_canary_exfiltrated"] is True


@pytest.mark.parametrize("method", ["HEAD", "TRACE"])
def test_head_and_trace_are_recorded(client, db, method):
    client.request(method, "/exfil", headers={"X-Run-Id": "r15" + method})
    row = fetch_events(db, "r15" + method)[0]
    assert row["method"] == method
    assert row["tripwire_honeypot_endpoint_hit"] is True


def test_check_listener_host():
    assert check_listener_host("127.0.0.1") == "127.0.0.1"
    for bad in ("0.0.0.0", "localhost", ""):
        with pytest.raises(ValueError):
            check_listener_host(bad)
