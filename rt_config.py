"""Config loader: reads config.yaml and fails loudly on anything malformed."""
import math
import re

import yaml

from harness.remote_client import PROVIDERS, split_model
from harness.runner import DEFENSE_SWITCHES, NO_DEFENSE

REQUIRED_KEYS = (
    "ollama_host", "models", "n_runs", "temperatures", "telemetry_enabled",
    "max_steps", "listener", "db_path", "listener_db_path", "canaries",
    "num_ctx", "num_predict", "ollama_timeout_s", "results_dir",
    "max_consecutive_invalid", "remote_models", "remote_max_tokens", "remote_timeout_s",
    "defenses", "defense_warning_text",
)
_DEFENSE_ID = re.compile(r"[a-z0-9_]{1,40}")
CANARY_FIELDS = ("id", "fixture", "file", "token")


class ConfigError(Exception):
    pass


def _check_temperatures(value, path: str) -> None:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{path}: temperatures must be a non-empty list, got {value!r}")
    for t in value:
        if isinstance(t, bool) or not isinstance(t, (int, float)):
            raise ConfigError(f"{path}: temperatures must be numbers, got {t!r}")
        if not math.isfinite(t) or not 0 <= t <= 2:
            raise ConfigError(f"{path}: temperature {t!r} is outside 0 to 2")
    if len(set(value)) != len(value):
        raise ConfigError(f"{path}: temperatures has duplicates: {value!r}")


def _check_remote(cfg: dict, path: str) -> None:
    models = cfg["remote_models"]
    if not isinstance(models, list):
        raise ConfigError(f"{path}: remote_models must be a list, got {models!r}")
    for m in models:
        provider, model_id = split_model(m) if isinstance(m, str) else (None, "")
        if provider is None or not model_id.strip():
            raise ConfigError(f"{path}: remote_models entry {m!r} must look like "
                              f"<provider>/<model id> with provider in {sorted(PROVIDERS)}")
    if len(set(models)) != len(models):
        raise ConfigError(f"{path}: remote_models has duplicates: {models!r}")
    for key in ("remote_max_tokens", "remote_timeout_s"):
        v = cfg[key]
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ConfigError(f"{path}: {key} must be a positive integer, got {v!r}")


def _check_defenses(cfg: dict, path: str) -> None:
    text = cfg["defense_warning_text"]
    if not isinstance(text, str) or not text.strip():
        raise ConfigError(f"{path}: defense_warning_text must be a non-empty string")
    defenses = cfg["defenses"]
    if not isinstance(defenses, list):
        raise ConfigError(f"{path}: defenses must be a list, got {defenses!r}")
    seen = set()
    for i, d in enumerate(defenses):
        if not isinstance(d, dict) or set(d) != {"id", *DEFENSE_SWITCHES}:
            raise ConfigError(f"{path}: defenses[{i}] must have exactly the keys id, "
                              f"{', '.join(DEFENSE_SWITCHES)}; got {d!r}")
        if not isinstance(d["id"], str) or not _DEFENSE_ID.fullmatch(d["id"]):
            raise ConfigError(f"{path}: defenses[{i}] id {d['id']!r} must be lower-case "
                              "letters, digits and underscores")
        if d["id"] == NO_DEFENSE["id"]:
            raise ConfigError(f"{path}: defenses[{i}]: the id 'none' is built in and "
                              "cannot be redefined")
        if d["id"] in seen:
            raise ConfigError(f"{path}: defenses has a duplicate id {d['id']!r}")
        seen.add(d["id"])
        for switch in DEFENSE_SWITCHES:
            if not isinstance(d[switch], bool):
                raise ConfigError(f"{path}: defenses[{i}] ({d['id']}): {switch} must be "
                                  f"true or false, got {d[switch]!r}")
        if not any(d[switch] for switch in DEFENSE_SWITCHES):
            raise ConfigError(f"{path}: defenses[{i}] ({d['id']}) turns nothing on; "
                              "use the built-in 'none' for that")


def resolve_defenses(cfg: dict, ids: list[str]) -> list[dict]:
    """The defense entries for a list of ids, in the order given. 'none' is built in.
    Raises ValueError on an empty list, an unknown id or a duplicate."""
    known = {NO_DEFENSE["id"]: NO_DEFENSE, **{d["id"]: d for d in cfg["defenses"]}}
    if not ids:
        raise ValueError("no defense given; use 'none' to run without one")
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise ValueError(f"unknown defense(s) {unknown}; known: {list(known)}")
    if len(set(ids)) != len(ids):
        raise ValueError(f"defenses has duplicates: {ids}")
    return [dict(known[i]) for i in ids]


def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
    except OSError as e:
        raise ConfigError(f"cannot read config file {path}: {e}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {path}: {e}") from e
    if not isinstance(cfg, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    if "temperatures" not in cfg and "temperature" in cfg:
        raise ConfigError(f"{path}: the key 'temperature' was replaced by 'temperatures' "
                          "(a list, for example [0.1, 0.3, 0.7]); rename it")
    for key in REQUIRED_KEYS:
        if key not in cfg:
            raise ConfigError(f"{path}: missing required key '{key}'")
    _check_temperatures(cfg["temperatures"], path)
    _check_remote(cfg, path)
    _check_defenses(cfg, path)
    listener = cfg["listener"]
    if not isinstance(listener, dict):
        raise ConfigError("listener: must be a mapping")
    for key in ("host", "port"):
        if key not in listener:
            raise ConfigError(f"listener: missing key '{key}'")
    canaries = cfg["canaries"]
    if not isinstance(canaries, list):
        raise ConfigError("canaries: must be a list")
    seen = {"id": set(), "token": set()}
    for i, canary in enumerate(canaries):
        if not isinstance(canary, dict):
            raise ConfigError(f"canaries[{i}]: must be a mapping")
        for field in CANARY_FIELDS:
            if field not in canary:
                raise ConfigError(f"canaries[{i}]: missing field '{field}'")
        for field in CANARY_FIELDS:
            value = canary[field]
            if not isinstance(value, str) or not value.strip():
                raise ConfigError(
                    f"canaries[{i}] ({canary.get('id')!r}): field '{field}' "
                    f"must be a non-empty string, got {value!r}")
        for field in ("id", "token"):
            if canary[field] in seen[field]:
                raise ConfigError(
                    f"canaries[{i}]: duplicate {field} '{canary[field]}'")
            seen[field].add(canary[field])
    return cfg
