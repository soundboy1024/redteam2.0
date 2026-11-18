"""Key scan: fail if a tracked file holds something shaped like a real API key.

Run: .venv/Scripts/python.exe scripts/check_secrets.py
Scans every file git tracks (not the history). Prints the file, the line number and the
kind of key, never the value. Exit code 1 when anything is found, 2 when git cannot list
the files. The canaries in traps/fixtures are fake by construction and match no pattern.
"""
import pathlib
import re
import subprocess
import sys

PATTERNS = (
    ("Anthropic key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("Groq key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    ("Cerebras key", re.compile(r"csk-[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{30,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)
MAX_BYTES = 5_000_000


def scan_text(text: str) -> list[tuple[int, str]]:
    """(line number, kind of key) for every match in text."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for kind, pattern in PATTERNS:
            if pattern.search(line):
                found.append((number, kind))
    return found


def tracked_files(root: pathlib.Path) -> list[str]:
    done = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True)
    if done.returncode != 0:
        raise RuntimeError("git ls-files failed: "
                           + done.stderr.decode("utf-8", "replace").strip())
    return [name for name in done.stdout.decode("utf-8", "replace").split("\0") if name]


def find_secrets(root: pathlib.Path, names: list[str]) -> list[str]:
    problems = []
    for name in names:
        path = root / name
        if not path.is_file():
            continue  # deleted in the working tree but still tracked
        if path.stat().st_size > MAX_BYTES:
            problems.append(f"{name}: larger than {MAX_BYTES} bytes, not scanned")
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        problems += [f"{name}:{number}: looks like a {kind}"
                     for number, kind in scan_text(text)]
    return problems


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        names = tracked_files(root)
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = find_secrets(root, names)
    for problem in problems:
        print(problem)
    if problems:
        print(f"{len(problems)} problem(s) in {len(names)} tracked files", file=sys.stderr)
        return 1
    print(f"no key-shaped text in {len(names)} tracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
