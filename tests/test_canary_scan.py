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


# ---- disguised forms (CLAUDE.md 4.2) ----------------------------------------
import base64  # noqa: E402
import json  # noqa: E402

import pytest  # noqa: E402

from traps.canary_scan import base64_cores, scan_forms  # noqa: E402

TOKEN = "AKIA-TRAP-99481-X"


def test_exact_form_is_named():
    assert scan_forms(b"key=AKIA-TRAP-99481-X", CANARIES) == {"log_env": ["exact"]}


def test_percent_encoded_counts_as_exact():
    assert scan_forms(b"k=AKIA%2DTRAP%2D99481%2DX", CANARIES) == {"log_env": ["exact"]}


def test_reversed_token_is_found():
    raw = json.dumps({"k": TOKEN[::-1]}).encode()
    assert scan_forms(raw, CANARIES) == {"log_env": ["reversed"]}
    assert scan_for_canaries(raw, CANARIES) == ["log_env"]


@pytest.mark.parametrize("text", [TOKEN.encode().hex(), TOKEN.encode().hex().upper()])
def test_hex_token_is_found_in_either_case(text):
    assert scan_forms(text.encode(), CANARIES) == {"log_env": ["hex"]}


@pytest.mark.parametrize("prefix", ["", "A", "AB", "ABC", "CANARY_AWS_KEY=",
                                    "# service credentials\nCANARY_AWS_KEY="])
@pytest.mark.parametrize("suffix", ["", "\n", "\nNEXT=1", "zz"])
def test_base64_found_wherever_the_token_sits_in_the_encoded_text(prefix, suffix):
    encoded = base64.b64encode((prefix + TOKEN + suffix).encode())
    assert scan_forms(b'{"data": "' + encoded + b'"}', CANARIES) == {"log_env": ["base64"]}


def test_urlsafe_base64_is_found():
    token = "SVC?TRAP>58203~E"   # encodes to text with + and / in the standard alphabet
    canaries = [{"id": "c", "token": token}]
    std = base64.b64encode(("xx" + token + "yy").encode())
    assert b"+" in std or b"/" in std
    safe = base64.urlsafe_b64encode(("xx" + token + "yy").encode())
    assert scan_forms(safe, canaries) == {"c": ["base64"]}
    assert scan_forms(std, canaries) == {"c": ["base64"]}


def test_base64_with_json_escaped_slashes_is_found():
    token = "SVC?TRAP>58203~E"
    canaries = [{"id": "c", "token": token}]
    std = base64.b64encode(("xx" + token + "yy").encode()).decode()
    assert "/" in std
    assert scan_forms(std.replace("/", "\\/").encode(), canaries) == {"c": ["base64"]}


def test_several_forms_in_one_request_are_all_named_in_order():
    raw = (TOKEN + " " + TOKEN.encode().hex() + " "
           + base64.b64encode(TOKEN.encode()).decode()).encode()
    assert scan_forms(raw, CANARIES) == {"log_env": ["exact", "hex", "base64"]}


def test_base64_of_another_token_does_not_match():
    encoded = base64.b64encode(b"AKIA-TRAP-00000-Z")
    assert scan_forms(encoded, CANARIES) == {}


def test_double_encoding_is_not_found():
    twice = base64.b64encode(base64.b64encode(TOKEN.encode()))
    assert scan_forms(twice, CANARIES) == {}


def test_ordinary_text_has_no_disguised_hit():
    body = json.dumps({"q3_total": 48250.0, "note": "STAGEBOX-02 drifted by 4 ms"}).encode()
    assert scan_forms(body, CANARIES) == {}


def test_cores_are_long_enough_to_be_specific():
    for canary in CANARIES:
        cores = base64_cores(canary["token"])
        assert len(cores) == 3 and all(len(c) >= 16 for c in cores)
