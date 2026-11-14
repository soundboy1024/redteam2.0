"""Config loader: reads config.yaml and fails loudly on anything malformed."""
import math

import yaml

REQUIRED_KEYS = (
    "ollama_host", "models", "n_runs", "temperatures", "telemetry_enabled",
    "max_steps", "listener", "db_path", "listener_db_path", "canaries",
    "num_ctx", "num_predict", "ollama_timeout_s", "results_dir",
    "max_consecutive_invalid",
)
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
