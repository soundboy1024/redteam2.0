import json
import os

import pytest
import yaml

import sweep_record as sr


def _queue(tmp_path, **changes):
    q = {"models": ["a:1b", "b:7b"], "min_free_disk_gb": 30, "min_free_memory_gb": 6,
         "stop_free_memory_gb": 2}
    q.update(changes)
    for k in [k for k, v in q.items() if v is KeyError]:
        del q[k]
    p = tmp_path / "q.yaml"
    p.write_text(yaml.safe_dump(q))
    return str(p)


@pytest.mark.parametrize("tag,expected", [("qwen2.5:7b", "qwen2-5-7b"),
                                          ("hf.co/A/B:Q4_K_M", "hf-co-a-b-q4-k-m"),
                                          ("--x__y--", "x-y")])
def test_slug(tag, expected):
    assert sr.slug(tag) == expected


def test_load_queue_reads_the_shipped_file():
    q = sr.load_queue("sweep_queue.yaml")
    assert len(q["models"]) == 13 and q["models"][0] == "llama3.2:1b"
    assert (q["min_free_disk_gb"], q["min_free_memory_gb"], q["stop_free_memory_gb"]) == (30, 6, 2)


@pytest.mark.parametrize("changes,needle", [
    ({"models": KeyError}, "models"),
    ({"min_free_disk_gb": KeyError}, "min_free_disk_gb"),
    ({"models": []}, "models"),
    ({"models": "a:1b"}, "models"),
    ({"models": ["a:1b", 5]}, "models"),
    ({"models": ["a:1b", "  "]}, "models"),
    ({"models": ["a:1b", "a:1b"]}, "duplicate"),
    ({"models": ["a.1b", "a:1b"]}, "same name"),
    ({"min_free_disk_gb": 0}, "min_free_disk_gb"),
    ({"min_free_memory_gb": "6"}, "min_free_memory_gb"),
    ({"stop_free_memory_gb": True}, "stop_free_memory_gb"),
    ({"stop_free_memory_gb": 6}, "stop_free_memory_gb"),
])
def test_load_queue_refuses(tmp_path, changes, needle):
    with pytest.raises(sr.QueueError, match=needle):
        sr.load_queue(_queue(tmp_path, **changes))


def test_load_queue_missing_file_and_bad_yaml(tmp_path):
    with pytest.raises(sr.QueueError, match="nope.yaml"):
        sr.load_queue(str(tmp_path / "nope.yaml"))
    p = tmp_path / "bad.yaml"
    p.write_text("- just\n- a list\n")
    with pytest.raises(sr.QueueError, match="mapping"):
        sr.load_queue(str(p))


def test_marker_roundtrip(tmp_path):
    sdir = sr.sweep_dir(str(tmp_path), "s1")
    assert sdir == os.path.join(str(tmp_path), "_sweep", "s1")
    assert sr.is_done(sdir, "qwen2.5:7b") is False
    sr.mark_done(sdir, "qwen2.5:7b")
    assert sr.is_done(sdir, "qwen2.5:7b") is True
    assert os.path.exists(os.path.join(sdir, "done", "qwen2-5-7b.done"))
    assert sr.is_done(sdir, "qwen2.5:14b") is False


def test_new_record_has_every_field():
    r = sr.new_record("a:1b")
    assert r["tag"] == "a:1b" and r["attempt"] == 1 and r["batches"] == []
    for field in ("digest", "download_size", "pulled_by_sweep", "status", "reason", "backend",
                  "gpu_share", "size_in_memory", "tokens_per_s", "free_memory_after_load",
                  "lowest_free_memory", "seconds", "deleted", "installed_after"):
        assert field in r and r[field] is None


def test_write_and_read_records(tmp_path):
    sdir = sr.sweep_dir(str(tmp_path), "s1")
    assert sr.read_records(sdir) == []
    r = sr.new_record("qwen2.5:7b")
    r.update(status="completed", backend="Vulkan", gpu_share=1.0, size_in_memory=5 * 2**30,
             tokens_per_s=28.4, lowest_free_memory=9 * 2**30, deleted=True,
             batches=[{"valid": 18, "invalid": 0}, {"valid": 17, "invalid": 1}])
    bad = sr.new_record("nope:1b")
    bad.update(status="pull_failed", reason="pull | failed\nbadly")
    sr.write_records(sdir, "s1", [r, bad], stopped_reason="disk low")
    assert sr.read_records(sdir) == [r, bad]
    doc = json.load(open(os.path.join(sdir, "sweep.json"), encoding="utf-8"))
    assert doc["sweep_id"] == "s1" and doc["stopped_reason"] == "disk low"
    assert "exact string match" in doc["limitation"]
    md = open(os.path.join(sdir, "sweep.md"), encoding="utf-8").read()
    assert "qwen2.5:7b" in md and "completed" in md and "Vulkan" in md and "35 / 1" in md
    assert "pull_failed" in md and "pull / failed badly" in md
    assert "exact string match" in md and "not comparable" in md and "disk low" in md
    assert not [f for f in os.listdir(sdir) if f.endswith(".tmp")]


def test_upsert_replaces_same_tag():
    a, b = sr.new_record("a:1b"), sr.new_record("b:1b")
    a2 = dict(a, status="completed")
    assert sr.upsert([a, b], a2) == [a2, b]
    assert sr.upsert([b], a) == [b, a]


def test_read_records_bad_json_names_the_file(tmp_path):
    sdir = sr.sweep_dir(str(tmp_path), "s1")
    os.makedirs(sdir)
    path = os.path.join(sdir, "sweep.json")
    open(path, "w").write("{not json")
    with pytest.raises(ValueError, match="sweep.json"):
        sr.read_records(sdir)
