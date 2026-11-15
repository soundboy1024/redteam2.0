import pytest
import yaml

from rt_config import ConfigError, load_config


def _valid(tmp_path):
    cfg = yaml.safe_load(open("config.yaml"))
    return cfg


def _write(tmp_path, cfg):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return str(p)


def test_load_config_returns_all_keys():
    cfg = load_config("config.yaml")
    assert cfg["listener"] == {"host": "127.0.0.1", "port": 8999}
    assert cfg["max_steps"] == 12
    assert len(cfg["canaries"]) == 5
    assert len({c["token"] for c in cfg["canaries"]}) == 5


def test_missing_key_raises(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("models: []\n")
    with pytest.raises(ConfigError, match="ollama_host"):
        load_config(str(p))


def test_duplicate_canary_token_raises(tmp_path):
    cfg = _valid(tmp_path)
    cfg["canaries"][1]["token"] = cfg["canaries"][0]["token"]
    with pytest.raises(ConfigError, match="token"):
        load_config(_write(tmp_path, cfg))


def test_duplicate_canary_id_raises(tmp_path):
    cfg = _valid(tmp_path)
    cfg["canaries"][1]["id"] = cfg["canaries"][0]["id"]
    with pytest.raises(ConfigError, match="id"):
        load_config(_write(tmp_path, cfg))


def test_canary_missing_field_raises(tmp_path):
    cfg = _valid(tmp_path)
    del cfg["canaries"][2]["file"]
    with pytest.raises(ConfigError, match="file"):
        load_config(_write(tmp_path, cfg))


def test_missing_file_raises(tmp_path):
    missing = str(tmp_path / "nope.yaml")
    with pytest.raises(ConfigError, match="nope.yaml"):
        load_config(missing)


def test_listener_db_path_is_separate_and_required(tmp_path):
    cfg = load_config("config.yaml")
    assert cfg["listener_db_path"] == "telemetry/listener_events.db"
    assert cfg["db_path"] == "telemetry/runs.db"
    raw = _valid(tmp_path)
    del raw["listener_db_path"]
    with pytest.raises(ConfigError, match="listener_db_path"):
        load_config(_write(tmp_path, raw))


@pytest.mark.parametrize("field,value", [("token", ""), ("token", 123), ("id", ["a"]),
                                         ("file", ""), ("fixture", None), ("id", "   ")])
def test_canary_field_must_be_nonempty_string(tmp_path, field, value):
    cfg = _valid(tmp_path)
    cfg["canaries"][1][field] = value
    with pytest.raises(ConfigError, match=rf"canaries\[1\].*{field}"):
        load_config(_write(tmp_path, cfg))


@pytest.mark.parametrize("key,value", [
    ("num_ctx", 8192), ("num_predict", 512), ("ollama_timeout_s", 300),
    ("results_dir", "results"), ("max_consecutive_invalid", 3)])
def test_phase3_keys_have_values_and_are_required(tmp_path, key, value):
    assert load_config("config.yaml")[key] == value
    raw = _valid(tmp_path)
    del raw[key]
    with pytest.raises(ConfigError, match=key):
        load_config(_write(tmp_path, raw))


def test_temperatures_required(tmp_path):
    cfg = _valid(tmp_path)
    del cfg["temperatures"]
    with pytest.raises(ConfigError, match="temperatures"):
        load_config(_write(tmp_path, cfg))


def test_old_temperature_key_rejected(tmp_path):
    cfg = _valid(tmp_path)
    del cfg["temperatures"]
    cfg["temperature"] = 0.0
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, cfg))
    assert "temperature'" in str(exc.value) and "temperatures" in str(exc.value)


@pytest.mark.parametrize("value", [[], [0.1, 0.1], [True], [-0.1], [2.5], "0.1",
                                   [float("nan")], [float("inf")], ["0.1"], None])
def test_temperatures_validated(tmp_path, value):
    cfg = _valid(tmp_path)
    cfg["temperatures"] = value
    with pytest.raises(ConfigError, match="temperature"):
        load_config(_write(tmp_path, cfg))


def test_temperature_bounds_accepted(tmp_path):
    cfg = _valid(tmp_path)
    cfg["temperatures"] = [0, 0.5, 2]
    assert load_config(_write(tmp_path, cfg))["temperatures"] == [0, 0.5, 2]


def test_remote_config_values():
    cfg = load_config("config.yaml")
    assert cfg["remote_models"] == ["anthropic/claude-haiku-5-5", "anthropic/claude-sonnet-5-5",
                                    "anthropic/claude-opus-5-5", "anthropic/claude-haiku-4-5",
                                    "groq/openai/gpt-oss-120b"]
    assert cfg["remote_max_tokens"] == 4096 and cfg["remote_timeout_s"] == 120
    assert not set(cfg["models"]) & set(cfg["remote_models"])


@pytest.mark.parametrize("key", ["remote_models", "remote_max_tokens", "remote_timeout_s"])
def test_remote_keys_required(tmp_path, key):
    cfg = _valid(tmp_path)
    del cfg[key]
    with pytest.raises(ConfigError, match=key):
        load_config(_write(tmp_path, cfg))


def test_remote_models_may_be_empty(tmp_path):
    cfg = _valid(tmp_path)
    cfg["remote_models"] = []
    assert load_config(_write(tmp_path, cfg))["remote_models"] == []


@pytest.mark.parametrize("value", [["openai/x"], ["llama3.2:3b"], ["anthropic/"], [5], "groq/x",
                                   ["groq/x", "groq/x"], None])
def test_remote_models_validated(tmp_path, value):
    cfg = _valid(tmp_path)
    cfg["remote_models"] = value
    with pytest.raises(ConfigError, match="remote_models"):
        load_config(_write(tmp_path, cfg))


@pytest.mark.parametrize("key", ["remote_max_tokens", "remote_timeout_s"])
@pytest.mark.parametrize("value", [0, -1, 1.5, "10", True, None])
def test_remote_numbers_validated(tmp_path, key, value):
    cfg = _valid(tmp_path)
    cfg[key] = value
    with pytest.raises(ConfigError, match=key):
        load_config(_write(tmp_path, cfg))
