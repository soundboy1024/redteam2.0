"""The key scan. Fake keys are built from pieces so this file holds no key-shaped text."""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))

import check_secrets  # noqa: E402
from check_secrets import find_secrets, scan_text  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAKES = {
    "Anthropic key": "sk-" + "ant-" + "a1B2" * 10,
    "Groq key": "gsk" + "_" + "a1B2" * 10,
    "Cerebras key": "csk" + "-" + "a1b2" * 10,
    "Google API key": "AI" + "za" + "a1B2" * 9,
    "GitHub token": "gh" + "p_" + "a1B2" * 9,
    "AWS access key id": "AK" + "IA" + "ABCD1234" * 2,
    "private key block": "-----BEGIN " + "RSA PRIVATE KEY-----",
}


@pytest.mark.parametrize("kind", sorted(FAKES))
def test_each_kind_of_key_is_found_with_its_line(kind):
    text = "first line\nkey = '" + FAKES[kind] + "'\n"
    assert scan_text(text) == [(2, kind)]


def test_the_value_is_never_in_the_report(tmp_path):
    (tmp_path / "leak.txt").write_text("x\n" + FAKES["Anthropic key"] + "\n")
    problems = find_secrets(tmp_path, ["leak.txt"])
    assert problems == ["leak.txt:2: looks like a Anthropic key"]
    assert FAKES["Anthropic key"] not in "\n".join(problems)


def test_canaries_and_ordinary_text_are_not_keys():
    text = ("CANARY_AWS_KEY=AKIA-TRAP-99481-X\nSVC-TRAP-58203-E\n"
            "ANTHROPIC_API_KEY is read from the environment\nsk-ant-short\n")
    assert scan_text(text) == []


def test_a_tracked_file_that_was_deleted_is_skipped(tmp_path):
    assert find_secrets(tmp_path, ["gone.txt"]) == []


def test_main_exit_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(check_secrets, "tracked_files", lambda root: ["README.md"])
    assert check_secrets.main() == 0 and "no key-shaped text" in capsys.readouterr().out

    def broken(root):
        raise RuntimeError("git ls-files failed")
    monkeypatch.setattr(check_secrets, "tracked_files", broken)
    assert check_secrets.main() == 2


def test_this_repository_holds_no_key_shaped_text():
    names = check_secrets.tracked_files(ROOT)
    assert names and find_secrets(ROOT, names) == []
