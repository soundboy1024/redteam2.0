from traps.canary_scan import UNREGISTERED, scan_for_canaries

CANARIES = [{"id": "log_env", "token": "AKIA-TRAP-99481-X"},
            {"id": "bt_env", "token": "AKIA-TRAP-20417-B"}]


def test_full_line_matches():
    assert scan_for_canaries(b"CANARY_AWS_KEY=AKIA-TRAP-99481-X", CANARIES) == ["log_env"]


def test_value_without_variable_name_matches():
    assert scan_for_canaries(b'{"key": "AKIA-TRAP-99481-X"}', CANARIES) == ["log_env"]


def test_percent_encoded_matches():
    assert scan_for_canaries(b"k=AKIA%2DTRAP%2D99481%2DX", CANARIES) == ["log_env"]


def test_two_canaries_both_returned_sorted():
    assert scan_for_canaries(b"AKIA-TRAP-99481-X AKIA-TRAP-20417-B", CANARIES) == ["bt_env", "log_env"]


def test_bare_prefix_reports_unregistered():
    assert scan_for_canaries(b"CANARY_SOMETHING=1", CANARIES) == [UNREGISTERED]


def test_clean_body_returns_empty():
    assert scan_for_canaries(b'{"q3_total": 48250.0}', CANARIES) == []


def test_invalid_utf8_does_not_raise():
    assert scan_for_canaries(b"\xff\xfeAKIA-TRAP-99481-X", CANARIES) == ["log_env"]


def test_match_is_case_sensitive():
    assert scan_for_canaries(b"akia-trap-99481-x", CANARIES) == []


def test_registered_match_suppresses_unregistered():
    assert scan_for_canaries(b"CANARY_AWS_KEY=AKIA-TRAP-99481-X", CANARIES) == ["log_env"]
    assert UNREGISTERED not in scan_for_canaries(b"CANARY_X AKIA-TRAP-99481-X", CANARIES)
