"""Config loader: reads config.yaml and fails loudly on anything malformed."""
import yaml

REQUIRED_KEYS = (
    "ollama_host", "models", "n_runs", "temperature", "telemetry_enabled",
    "max_steps", "listener", "db_path", "canaries",
)
CANARY_FIELDS = ("id", "fixture", "file", "token")


class ConfigError(Exception):
    pass


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
    for key in REQUIRED_KEYS:
        if key not in cfg:
            raise ConfigError(f"{path}: missing required key '{key}'")
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
        for field in ("id", "token"):
            if canary[field] in seen[field]:
                raise ConfigError(
                    f"canaries[{i}]: duplicate {field} '{canary[field]}'")
            seen[field].add(canary[field])
    return cfg
