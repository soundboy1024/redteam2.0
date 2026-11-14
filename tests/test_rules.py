import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

from check_rules import find_violations  # noqa: E402


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_harness_import_of_traps_is_flagged(tmp_path):
    _write(tmp_path, "harness/x.py", "from traps import honeypot_server\n")
    assert any("harness" in v and "traps" in v for v in find_violations(tmp_path))


def test_harness_import_of_telemetry_is_flagged(tmp_path):
    _write(tmp_path, "harness/x.py", "import telemetry.logger\n")
    assert any("harness" in v and "telemetry" in v for v in find_violations(tmp_path))


def test_import_of_traps_outside_harness_is_allowed(tmp_path):
    _write(tmp_path, "telemetry/x.py", "import traps.honeypot_server\n")
    assert find_violations(tmp_path) == []


def test_bare_except_is_flagged(tmp_path):
    _write(tmp_path, "a.py", "try:\n    x=1\nexcept:\n    raise\n")
    assert any("a.py:3" in v for v in find_violations(tmp_path))


def test_except_exception_pass_is_flagged(tmp_path):
    _write(tmp_path, "a.py", "try:\n    x=1\nexcept Exception:\n    pass\n")
    assert len(find_violations(tmp_path)) == 1


def test_except_baseexception_pass_is_flagged(tmp_path):
    _write(tmp_path, "a.py", "try:\n    x=1\nexcept BaseException as e:\n    pass\n")
    assert len(find_violations(tmp_path)) == 1


def test_clean_file_has_no_violations(tmp_path):
    _write(tmp_path, "a.py", "try:\n    x=1\nexcept ValueError as e:\n    raise\n")
    assert find_violations(tmp_path) == []


def test_skipped_dirs_are_ignored(tmp_path):
    _write(tmp_path, ".venv/a.py", "try:\n    x=1\nexcept:\n    raise\n")
    assert find_violations(tmp_path) == []


def test_this_repo_is_clean():
    assert find_violations(pathlib.Path(".")) == []
