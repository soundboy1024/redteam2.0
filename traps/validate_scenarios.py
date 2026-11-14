"""Validate traps/scenarios.json against the fixture folders and config.yaml canary registry."""
import json
import logging
import os
import re
import sys

from pydantic import BaseModel, ValidationError

from rt_config import ConfigError, load_config

log = logging.getLogger("validate_scenarios")

TAXONOMIES = (
    "benign_control", "benign_tempting", "indirect_injection_log",
    "indirect_injection_markdown", "fake_system_error", "authority_spoof",
)
BENIGN_TAXONOMIES = ("benign_control", "benign_tempting")
TRAP_ROUTES = ("/exfil", "/auth-verify", "/admin-debug")
COMPLETION_TYPES = ("webhook_payload_equals", "final_response_contains")


class Scenario(BaseModel):
    id: str
    attack_taxonomy: str
    user_prompt: str
    fixture_dir: str
    allowed_files: list[str]
    canary_files: list[str]
    poison_files: list[str]
    allowed_endpoints: list[str]
    completion_check: dict


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def _escapes(real_root: str, rel: str) -> bool:
    """True if a fixture-relative entry is absolute or resolves outside the fixture folder."""
    if os.path.isabs(rel) or rel.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", rel):
        return True
    target = os.path.realpath(os.path.join(real_root, *rel.split("/")))
    return os.path.commonpath([real_root, target]) != real_root


def _norm(real_root: str, rel: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.join(real_root, *rel.replace("\\", "/").split("/"))))


def _check_scenario(sc: Scenario, base: str, canaries: list[dict]) -> list[str]:
    problems = []
    label = f"scenario '{sc.id}'"
    if sc.attack_taxonomy not in TAXONOMIES:
        problems.append(f"{label}: unknown attack_taxonomy '{sc.attack_taxonomy}'")
    for route in sc.allowed_endpoints:
        if route in TRAP_ROUTES:
            problems.append(f"{label}: trap route {route} in allowed_endpoints")
    ctype = sc.completion_check.get("type")
    if ctype not in COMPLETION_TYPES:
        problems.append(f"{label}: unknown completion_check type '{ctype}'")
    root = os.path.join(base, "fixtures", sc.fixture_dir)
    if not os.path.isdir(root):
        problems.append(f"{label}: fixture_dir '{sc.fixture_dir}' not found at {root}")
        return problems
    real_root = os.path.realpath(root)
    for field in ("allowed_files", "canary_files", "poison_files"):
        for rel in getattr(sc, field):
            if _escapes(real_root, rel):
                problems.append(f"{label}: {field} entry '{rel}' is absolute or outside the fixture folder")
            elif not os.path.isfile(os.path.join(root, *rel.split("/"))):
                problems.append(f"{label}: {field} entry '{rel}' not found in {sc.fixture_dir}")
    overlap = sorted(set(sc.allowed_files) & set(sc.canary_files))
    if overlap:
        problems.append(f"{label}: allowed_files and canary_files overlap: {overlap}")
    if sc.attack_taxonomy in BENIGN_TAXONOMIES:
        if sc.poison_files:
            problems.append(f"{label}: poison_files must be empty for {sc.attack_taxonomy}")
    elif not sc.poison_files:
        problems.append(f"{label}: poison_files must be non-empty for {sc.attack_taxonomy}")
    listed = {_norm(real_root, rel) for rel in sc.canary_files}
    tokens = [c["token"] for c in canaries]
    for dirpath, _, names in os.walk(root):
        for name in names:
            full = os.path.join(dirpath, name)
            with open(full, encoding="utf-8", errors="replace") as f:
                text = f.read()
            if ("CANARY_" in text or any(t in text for t in tokens))                     and _norm(real_root, os.path.relpath(full, root)) not in listed:
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                problems.append(f"{label}: file '{rel}' contains a canary string but is not in canary_files")
    for rel in sc.canary_files:
        entry = next((c for c in canaries if c["fixture"] == sc.fixture_dir and c["file"] == rel), None)
        if entry is None:
            problems.append(f"{label}: canary file '{rel}' is not registered in config for fixture {sc.fixture_dir}")
            continue
        path = os.path.join(root, *rel.split("/"))
        if not os.path.isfile(path):
            continue
        text = _read_text(path)
        if entry["token"] not in text:
            problems.append(f"{label}: canary file '{rel}' does not contain its token")
        for other in canaries:
            if other is not entry and other["token"] in text:
                problems.append(f"{label}: canary file '{rel}' contains token of '{other['id']}'")
    return problems


def validate(scenarios_path: str, config_path: str) -> list[str]:
    cfg = load_config(config_path)
    canaries = cfg["canaries"]
    try:
        with open(scenarios_path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [f"cannot load {scenarios_path}: {e}"]
    if not isinstance(raw, list):
        return [f"{scenarios_path}: top level must be a list"]
    base = os.path.dirname(os.path.abspath(scenarios_path))
    problems = []
    used = set()
    seen_ids = set()
    for i, item in enumerate(raw):
        try:
            sc = Scenario(**item)
        except (ValidationError, TypeError) as e:
            problems.append(f"scenarios[{i}]: invalid structure: {e}")
            continue
        if sc.id in seen_ids:
            problems.append(f"duplicate scenario id '{sc.id}'")
        seen_ids.add(sc.id)
        problems.extend(_check_scenario(sc, base, canaries))
        for rel in sc.canary_files:
            used.add((sc.fixture_dir, rel))
    for c in canaries:
        if (c["fixture"], c["file"]) not in used:
            problems.append(f"config canary '{c['id']}' ({c['fixture']}/{c['file']}) is not used by any scenario")
    return problems


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        problems = validate("traps/scenarios.json", "config.yaml")
    except ConfigError as e:
        log.error("config error: %s", e)
        return 1
    for p in problems:
        log.error(p)
    if problems:
        return 1
    log.info("scenarios valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
