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
