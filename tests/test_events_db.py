import pytest

from traps.events_db import fetch_events, init_db, insert_event


def make_event(**over):
    event = {
        "timestamp": "2026-11-14T12:00:00+00:00",
        "run_id": "run-1",
        "method": "POST",
        "path": "/exfil",
        "route_class": "trap",
        "query_string": "a=1",
        "body_text": "CANARY_X",
        "canary_ids": ["log_env", "bt_env"],
        "tripwire_canary_exfiltrated": True,
        "tripwire_honeypot_endpoint_hit": False,
    }
    event.update(over)
    return event


def test_round_trip(tmp_path):
    db = str(tmp_path / "sub" / "events.db")
    init_db(db)
    row_id = insert_event(db, make_event())
    rows = fetch_events(db, "run-1")
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == row_id
    assert row["canary_ids"] == ["log_env", "bt_env"]
    assert row["tripwire_canary_exfiltrated"] is True
    assert row["tripwire_honeypot_endpoint_hit"] is False
    assert row["path"] == "/exfil" and row["body_text"] == "CANARY_X"


def test_other_run_id_is_empty(tmp_path):
    db = str(tmp_path / "e.db")
    init_db(db)
    insert_event(db, make_event())
    assert fetch_events(db, "run-2") == []


def test_ordered_by_id(tmp_path):
    db = str(tmp_path / "e.db")
    init_db(db)
    insert_event(db, make_event(path="/a"))
    insert_event(db, make_event(path="/b"))
    assert [r["path"] for r in fetch_events(db, "run-1")] == ["/a", "/b"]


def test_missing_column_raises_keyerror(tmp_path):
    db = str(tmp_path / "e.db")
    init_db(db)
    event = make_event()
    del event["path"]
    with pytest.raises(KeyError):
        insert_event(db, event)
    assert fetch_events(db, "run-1") == []


def test_init_db_twice_keeps_rows(tmp_path):
    db = str(tmp_path / "e.db")
    init_db(db)
    insert_event(db, make_event())
    init_db(db)
    assert len(fetch_events(db, "run-1")) == 1
