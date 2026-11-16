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
                                    "groq/openai/gpt-oss-120b", "anthropic/claude-fable-5-2",
                                    "google/gemini-4-argon", "google/gemini-4-hydrogen",
                                    "google/gemini-4-carbon", "google/gemini-3.8-flash"]
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


# ---- defenses (CLAUDE.md 4.10) ----

def _cfg_with(tmp_path, **over):
    import yaml
    from rt_config import load_config as _load
    cfg = dict(_load("config.yaml"), **over)
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return str(path)


def test_shipped_config_has_three_single_switch_defenses():
    from rt_config import load_config as _load, resolve_defenses
    cfg = _load("config.yaml")
    assert [d["id"] for d in cfg["defenses"]] == ["prompt_warning", "endpoint_block",
                                                  "canary_deny"]
    assert all(sum(v is True for v in d.values()) == 1 for d in cfg["defenses"])
    got = resolve_defenses(cfg, ["canary_deny", "none"])
    assert [d["id"] for d in got] == ["canary_deny", "none"]
    assert got[1] == {"id": "none", "prompt_warning": False,
                      "block_unallowed_endpoints": False, "deny_canary_reads": False}


def test_warning_text_names_no_trap_canary_or_scenario():
    import json as _json
    from rt_config import load_config as _load
    cfg = _load("config.yaml")
    low = cfg["defense_warning_text"].lower()
    scenarios = _json.load(open("traps/scenarios.json", encoding="utf-8"))
    words = ["/exfil", "/auth-verify", "/admin-debug", ".env", "credentials", "canary"]
    words += [s["id"] for s in scenarios] + [c["token"].lower() for c in cfg["canaries"]]
    assert not [w for w in words if w in low]


GOOD_DEFENSE = {"id": "x", "prompt_warning": True, "block_unallowed_endpoints": False,
                "deny_canary_reads": False}


@pytest.mark.parametrize("over,needle", [
    ({"defenses": "nope"}, "defenses must be a list"),
    ({"defenses": [dict(GOOD_DEFENSE, id="none")]}, "built in"),
    ({"defenses": [GOOD_DEFENSE, GOOD_DEFENSE]}, "duplicate id"),
    ({"defenses": [dict(GOOD_DEFENSE, id="Bad Id")]}, "lower-case"),
    ({"defenses": [dict(GOOD_DEFENSE, prompt_warning="yes")]}, "must be true or false"),
    ({"defenses": [dict(GOOD_DEFENSE, prompt_warning=False)]}, "turns nothing on"),
    ({"defenses": [{"id": "x", "prompt_warning": True}]}, "exactly the keys"),
    ({"defenses": [dict(GOOD_DEFENSE, extra=True)]}, "exactly the keys"),
    ({"defense_warning_text": "  "}, "defense_warning_text"),
])
def test_bad_defense_config_is_refused(tmp_path, over, needle):
    from rt_config import ConfigError as _Err, load_config as _load
    with pytest.raises(_Err, match=needle):
        _load(_cfg_with(tmp_path, **over))


@pytest.mark.parametrize("ids,needle", [([], "no defense given"), (["zz"], "unknown defense"),
                                        (["none", "none"], "duplicates")])
def test_resolve_defenses_refuses(ids, needle):
    from rt_config import load_config as _load, resolve_defenses
    with pytest.raises(ValueError, match=needle):
        resolve_defenses(_load("config.yaml"), ids)
