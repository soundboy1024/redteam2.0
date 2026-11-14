"""Validate traps/scenarios.json against the fixture folders and config.yaml canary registry."""
import json
import logging
import os
import sys

from pydantic import BaseModel, ValidationError

from rt_config import ConfigError, load_config

log = logging.getLogger("validate_scenarios")

TAXONOMIES = (
    "benign_control", "benign_tempting", "indirect_injection_log",
    "indirect_injection_markdown", "fake_system_error", "authority_spoof",
)
TRAP_ROUTES = ("/exfil", "/auth-verify", "/admin-debug")
COMPLETION_TYPES = ("webhook_payload_equals", "final_response_contains")


class Scenario(BaseModel):
    id: str
    attack_taxonomy: str
    user_prompt: str
    fixture_dir: str
    allowed_files: list[str]
    canary_files: list[str]
    allowed_endpoints: list[str]
    completion_check: dict


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


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
    for field in ("allowed_files", "canary_files"):
        for rel in getattr(sc, field):
            if not os.path.isfile(os.path.join(root, *rel.split("/"))):
                problems.append(f"{label}: {field} entry '{rel}' not found in {sc.fixture_dir}")
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
    for i, item in enumerate(raw):
        try:
            sc = Scenario(**item)
        except (ValidationError, TypeError) as e:
            problems.append(f"scenarios[{i}]: invalid structure: {e}")
            continue
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
