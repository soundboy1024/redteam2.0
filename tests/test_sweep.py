import json
import os

import pytest

import sweep
import sweep_probe
import sweep_record as sr

GB = 2 ** 30


class FakeProc:
    """A run_eval.py stand-in: writes batch.json at start, results at exit."""

    def __init__(self, world, bid, exit_code=0, rows=18, planned=18, aborted=False,
                 polls=1, invalid=0, results=True, on_poll=None, interrupt_at=None):
        self.world, self.bid = world, bid
        self.exit_code, self.rows, self.planned = exit_code, rows, planned
        self.aborted, self.invalid, self.results = aborted, invalid, results
        self.remaining, self.on_poll, self.interrupt_at = polls, on_poll, interrupt_at
        self.returncode, self.polled, self.killed = None, 0, False
        self.out_dir = os.path.join(world.results, bid)
        os.makedirs(self.out_dir)
        self._plan(ended_at=None, aborted=None)

    def _plan(self, **fields):
        plan = {"batch_id": self.bid, "planned_runs": self.planned, "pid": 4242,
                "pid_create_time": 1}
        plan.update(fields)
        with open(os.path.join(self.out_dir, "batch.json"), "w") as f:
            json.dump(plan, f)

    def _results(self, rows):
        doc = {"results": [{"valid": i >= self.invalid} for i in range(rows)]}
        with open(os.path.join(self.out_dir, "results.json"), "w") as f:
            json.dump(doc, f)

    def finish(self):
        if self.returncode is None:
            self.returncode = self.exit_code
            self._plan(ended_at="t", aborted=self.aborted)
            if self.results:
                self._results(self.rows)

    def kill_and_regrade(self):
        self.killed, self.returncode = True, 1
        self._plan(ended_at="t", aborted=True)
        self._results(5)

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        self.polled += 1
        if self.interrupt_at == self.polled:
            raise KeyboardInterrupt
        if self.on_poll:
            self.on_poll(self.polled)
        if self.remaining > 0:
            self.remaining -= 1
            return None
        self.finish()
        return self.returncode

    def wait(self, timeout=None):
        self.finish()
        return self.returncode


class World:
    def __init__(self, tmp_path, installed=()):
        self.results = str(tmp_path / "results")
        os.makedirs(self.results)
        self.names = {n: {"digest": "d-" + n, "size": 5 * GB} for n in installed}
        self.loaded_now, self.calls, self.procs = [], [], []
        self.free_now, self.free_after_load, self.disk = 20 * GB, None, 300 * GB
        self.pull_fail, self.load_fail, self.port = set(), set(), False
        self.unload_ok, self.delete_fail, self.batch_kwargs = True, False, {}
        self.before_delete = None
        self.settings = sweep.Settings(
            sweep_id="s1", root=str(tmp_path), python_exe="py", config_path="config.yaml",
            results_dir=self.results, num_ctx=8192, temperatures=[0.1, 0.3, 0.7],
            min_free_disk=30 * GB, min_free_memory=6 * GB, stop_free_memory=2 * GB)
        self.deps = sweep.Deps(
            installed=lambda: dict(self.names), loaded=lambda: list(self.loaded_now),
            pull=self.pull, load_check=self.load_check, unload=self.unload,
            delete=self.delete, free_memory=lambda: self.free_now,
            free_disk=lambda: self.disk, log_size=lambda: 100,
            backend=lambda offset: "Vulkan", start_batch=self.start_batch,
            stop_batch=self.stop_batch, read_plan=self.read_plan,
            port_open=lambda: self.port, sleep=lambda s: None)

    def pull(self, tag):
        self.calls.append(("pull", tag))
        if tag in self.pull_fail:
            raise sweep_probe.ProbeError("POST /api/pull returned an error: not found")
        self.names[tag] = {"digest": "d-" + tag, "size": 4 * GB}

    def load_check(self, tag):
        self.calls.append(("load_check", tag))
        if tag in self.load_fail:
            raise sweep_probe.ProbeError("POST /api/chat returned HTTP 500: no memory")
        self.loaded_now = [{"name": tag, "size": 8 * GB, "size_vram": 6 * GB}]
        if self.free_after_load is not None:
            self.free_now = self.free_after_load
        return {"tokens_per_s": 25.0}

    def unload(self, tag):
        self.calls.append(("unload", tag))
        if self.unload_ok:
            self.loaded_now = []
        return self.unload_ok

    def delete(self, tag):
        if self.before_delete:
            self.before_delete(tag)
        self.calls.append(("delete", tag))
        if self.delete_fail:
            raise sweep_probe.ProbeError("DELETE /api/delete returned HTTP 500")
        del self.names[tag]

    def start_batch(self, command, console_log):
        bid = command[command.index("--batch-id") + 1]
        self.calls.append(("batch", bid))
        kwargs = self.batch_kwargs.get(len(self.procs), {})
        proc = FakeProc(self, bid, **kwargs)
        proc.command = command
        self.procs.append(proc)
        return proc

    def stop_batch(self, plan):
        self.calls.append(("stop", plan["batch_id"]))
        [p for p in self.procs if p.bid == plan["batch_id"]][0].kill_and_regrade()
        return {"killed": True, "port_closed": True, "regrade_exit": 0, "regrade_output": ""}

    def read_plan(self, out_dir):
        path = os.path.join(out_dir, "batch.json")
        return json.load(open(path)) if os.path.exists(path) else None

    def run(self, tag, **kw):
        return sweep.run_model(tag, self.settings, self.deps, **kw)

    def kinds(self):
        return [c[0] for c in self.calls]


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def test_batch_id_and_retry_suffix():
    assert sweep.batch_id("s1", "qwen2.5:7b", 0.1, 1) == "sweep-s1-qwen2-5-7b-t01"
    assert sweep.batch_id("s1", "qwen2.5:7b", 0.7, 2) == "sweep-s1-qwen2-5-7b-t07-r2"


def test_completed_model_is_pulled_run_three_times_and_deleted(world):
    rec = world.run("a:1b")
    assert rec["status"] == "completed" and rec["reason"] is None
    assert world.kinds() == ["pull", "load_check", "batch", "unload", "batch", "unload",
                             "batch", "unload", "delete"]
    assert [b["batch_id"] for b in rec["batches"]] == [
        "sweep-s1-a-1b-t01", "sweep-s1-a-1b-t03", "sweep-s1-a-1b-t07"]
    assert all(b["ok"] and b["valid"] == 18 and b["invalid"] == 0 for b in rec["batches"])
    assert rec["pulled_by_sweep"] is True and rec["deleted"] is True
    assert rec["installed_after"] is False and "a:1b" not in world.names
    assert rec["backend"] == "Vulkan" and rec["gpu_share"] == 0.75
    assert rec["size_in_memory"] == 8 * GB and rec["tokens_per_s"] == 25.0
    assert rec["digest"] == "d-a:1b" and rec["download_size"] == 4 * GB
    assert rec["free_memory_after_load"] == 20 * GB and rec["lowest_free_memory"] == 20 * GB
    command = world.procs[0].command
    assert command[:2] == ["py", "run_eval.py"] and "--allow-any-model" in command
    assert command[command.index("--models") + 1] == "a:1b"
    assert command[command.index("--temperatures") + 1] == "0.1"


@pytest.mark.parametrize("installed,tag", [("a:1b", "a:1b"), ("llama3.2:latest", "llama3.2")])
def test_preinstalled_model_is_never_deleted(tmp_path, installed, tag):
    world = World(tmp_path, installed=[installed])
    rec = world.run(tag)
    assert rec["status"] == "completed" and rec["pulled_by_sweep"] is False
    assert rec["deleted"] is False and rec["installed_after"] is True
    assert "pull" not in world.kinds() and "delete" not in world.kinds()
    assert installed in world.names


def test_pull_failure_recorded_and_nothing_deleted(world):
    world.pull_fail.add("nope:1b")
    rec = world.run("nope:1b")
    assert rec["status"] == "pull_failed" and "not found" in rec["reason"]
    assert world.kinds() == ["pull"] and rec["deleted"] is False and rec["batches"] == []


def test_load_failure_deletes_what_it_pulled(world):
    world.load_fail.add("a:1b")
    rec = world.run("a:1b")
    assert rec["status"] == "load_failed" and "no memory" in rec["reason"]
    assert world.kinds() == ["pull", "load_check", "unload", "delete"]
    assert rec["deleted"] is True


def test_does_not_fit_runs_no_batch(world):
    world.free_after_load = 5 * GB
    rec = world.run("a:1b")
    assert rec["status"] == "does_not_fit" and "5.0 GB" in rec["reason"]
    assert "batch" not in world.kinds() and rec["deleted"] is True
    assert rec["free_memory_after_load"] == 5 * GB


def test_memory_watch_stops_the_batch(world):
    def drop(polled):
        if polled == 2:
            world.free_now = 1 * GB
    world.batch_kwargs[0] = {"polls": 5, "on_poll": drop}
    rec = world.run("a:1b")
    assert rec["status"] == "stopped_for_memory" and "1.0 GB" in rec["reason"]
    assert world.kinds() == ["pull", "load_check", "batch", "stop", "unload", "delete"]
    assert len(rec["batches"]) == 1 and rec["batches"][0]["ok"] is False
    assert rec["batches"][0]["valid"] == 5 and rec["lowest_free_memory"] == 1 * GB


@pytest.mark.parametrize("kwargs,needle", [
    ({"rows": 17}, "17 of 18"),
    ({"aborted": True}, "aborted"),
    ({"exit_code": 1}, "exit code 1"),
    ({"results": False}, "results.json"),
])
def test_bad_batch_is_batch_failed_and_stops_the_model(world, kwargs, needle):
    world.batch_kwargs[1] = kwargs
    rec = world.run("a:1b")
    assert rec["status"] == "batch_failed" and needle in rec["reason"]
    assert len(rec["batches"]) == 2 and rec["batches"][0]["ok"] and not rec["batches"][1]["ok"]
    assert world.kinds().count("batch") == 2 and rec["deleted"] is True


def test_invalid_runs_are_counted_not_failed(world):
    world.batch_kwargs[0] = {"invalid": 2}
    rec = world.run("a:1b")
    assert rec["status"] == "completed"
    assert (rec["batches"][0]["valid"], rec["batches"][0]["invalid"]) == (16, 2)


def test_unload_failure_is_recorded_and_stops_the_model(world):
    world.unload_ok = False
    rec = world.run("a:1b")
    assert rec["status"] == "batch_failed" and "did not unload" in rec["reason"]
    assert world.kinds().count("batch") == 1
    assert rec["deleted"] is False and "delete" not in world.kinds()


def test_delete_failure_is_recorded(world):
    world.delete_fail = True
    rec = world.run("a:1b")
    assert rec["status"] == "batch_failed" and "/api/delete" in rec["reason"]
    assert rec["deleted"] is False and rec["installed_after"] is True


def test_ctrl_c_during_a_batch_stops_it_and_cleans_up(world):
    world.batch_kwargs[0] = {"polls": 5, "interrupt_at": 2}
    rec = world.run("a:1b")
    assert rec["status"] == "stopped" and "interrupted" in rec["reason"]
    assert world.kinds() == ["pull", "load_check", "batch", "stop", "unload", "delete"]


def test_ctrl_c_during_pull_is_recorded(world):
    def interrupted(tag):
        raise KeyboardInterrupt
    world.deps.pull = interrupted
    rec = world.run("a:1b")
    assert rec["status"] == "stopped" and rec["pulled_by_sweep"] is not True
    assert rec["deleted"] is False


def test_save_is_called_before_pull_and_before_delete(world):
    saved = []
    world.before_delete = lambda tag: saved.append("delete")
    world.run("a:1b", save=lambda rec: saved.append((rec["status"], rec["pulled_by_sweep"])))
    assert saved[0] == (None, None)            # in progress, before the pull
    assert (None, True) in saved               # after the pull succeeded
    assert saved[-2:] == [("completed", True), "delete"]


def test_a_model_left_by_an_earlier_attempt_is_still_the_sweeps_to_delete(tmp_path):
    world = World(tmp_path, installed=["a:1b"])
    prior = sr.new_record("a:1b")
    prior.update(pulled_by_sweep=True, deleted=False, digest="d-a:1b")
    rec = world.run("a:1b", attempt=2, prior=prior)
    assert rec["pulled_by_sweep"] is True and rec["deleted"] is True
    assert "pull" not in world.kinds() and "a:1b" not in world.names
    assert rec["batches"][0]["batch_id"] == "sweep-s1-a-1b-t01-r2"
    # a prior attempt that never finished its pull gives no such claim
    os.makedirs(tmp_path / "w2")
    world2 = World(tmp_path / "w2", installed=["a:1b"])
    rec2 = world2.run("a:1b", attempt=2, prior=sr.new_record("a:1b"))
    assert rec2["pulled_by_sweep"] is False and "a:1b" in world2.names


@pytest.mark.parametrize("change,needle", [
    (lambda w: setattr(w, "port", True), "port"),
    (lambda w: setattr(w, "loaded_now", [{"name": "x:1b", "size": 1, "size_vram": 1}]), "x:1b"),
    (lambda w: setattr(w, "disk", 10 * GB), "disk"),
    (lambda w: setattr(w, "free_now", 3 * GB), "memory"),
])
def test_preflight_reasons(world, change, needle):
    sweep.preflight(world.settings, world.deps)
    change(world)
    with pytest.raises(sweep.Preflight, match=needle):
        sweep.preflight(world.settings, world.deps)


def test_preflight_when_ollama_is_unreachable(world):
    def down():
        raise sweep_probe.ProbeError("GET /api/ps failed: ConnectionError")
    world.deps.loaded = down
    with pytest.raises(sweep.Preflight, match="/api/ps"):
        sweep.preflight(world.settings, world.deps)


# ---- the loop ---------------------------------------------------------------

def _queue(*tags):
    return {"models": list(tags), "min_free_disk_gb": 30, "min_free_memory_gb": 6,
            "stop_free_memory_gb": 2}


def _sdir(world):
    return sr.sweep_dir(world.results, "s1")


def test_sweep_runs_the_queue_and_skips_done_models_on_restart(world):
    assert sweep.run_sweep(_queue("a:1b", "b:1b"), world.settings, world.deps) == 0
    assert [r["status"] for r in sr.read_records(_sdir(world))] == ["completed", "completed"]
    assert sr.is_done(_sdir(world), "a:1b") and sr.is_done(_sdir(world), "b:1b")
    world.calls.clear()
    assert sweep.run_sweep(_queue("a:1b", "b:1b", "c:1b"), world.settings, world.deps) == 0
    assert [c for c in world.calls if c[0] == "pull"] == [("pull", "c:1b")]
    assert len(sr.read_records(_sdir(world))) == 3


def test_failed_model_gets_no_marker_and_is_retried_with_new_batch_ids(world):
    world.batch_kwargs[0] = {"rows": 3}
    assert sweep.run_sweep(_queue("a:1b"), world.settings, world.deps) == 0
    assert not sr.is_done(_sdir(world), "a:1b")
    assert sr.read_records(_sdir(world))[0]["status"] == "batch_failed"
    assert sweep.run_sweep(_queue("a:1b"), world.settings, world.deps) == 0
    rec = sr.read_records(_sdir(world))[0]
    assert rec["status"] == "completed" and rec["attempt"] == 2
    assert rec["batches"][0]["batch_id"] == "sweep-s1-a-1b-t01-r2"
    assert sr.is_done(_sdir(world), "a:1b")


def test_preflight_failure_stops_before_the_next_model(world):
    world.disk = 10 * GB
    assert sweep.run_sweep(_queue("a:1b", "b:1b"), world.settings, world.deps) == 2
    assert world.calls == []
    doc = json.load(open(os.path.join(_sdir(world), "sweep.json")))
    assert "disk" in doc["stopped_reason"] and doc["records"] == []


def test_three_pull_or_load_failures_in_a_row_stop_the_sweep(world):
    world.pull_fail.update({"a:1b", "b:1b"})
    world.load_fail.add("c:1b")
    code = sweep.run_sweep(_queue("a:1b", "b:1b", "c:1b", "d:1b"), world.settings, world.deps)
    assert code == 3 and ("pull", "d:1b") not in world.calls
    doc = json.load(open(os.path.join(_sdir(world), "sweep.json")))
    assert "in a row" in doc["stopped_reason"] and len(doc["records"]) == 3


def test_two_failures_then_a_success_resets_the_count(world):
    world.pull_fail.update({"a:1b", "b:1b", "d:1b"})
    code = sweep.run_sweep(_queue("a:1b", "b:1b", "c:1b", "d:1b", "e:1b"), world.settings,
                           world.deps)
    assert code == 0 and ("pull", "e:1b") in world.calls


def test_record_is_on_disk_before_the_delete(world):
    seen = []

    def check(tag):
        records = sr.read_records(_sdir(world))
        seen.append([(r["tag"], r["status"]) for r in records])
    world.before_delete = check
    sweep.run_sweep(_queue("a:1b"), world.settings, world.deps)
    assert seen == [[("a:1b", "completed")]]


def test_ctrl_c_returns_130_leaves_no_marker_and_stops_the_queue(world):
    world.batch_kwargs[0] = {"polls": 5, "interrupt_at": 2}
    assert sweep.run_sweep(_queue("a:1b", "b:1b"), world.settings, world.deps) == 130
    assert not sr.is_done(_sdir(world), "a:1b")
    assert [r["status"] for r in sr.read_records(_sdir(world))] == ["stopped"]
    assert ("pull", "b:1b") not in world.calls


def test_memory_stop_moves_on_to_the_next_model(world):
    def drop(polled):
        world.free_now = 1 * GB if polled == 2 else world.free_now
    world.batch_kwargs[0] = {"polls": 5, "on_poll": drop}
    original_unload = world.unload

    def unload(tag):
        world.free_now = 20 * GB
        return original_unload(tag)
    world.deps.unload = unload
    assert sweep.run_sweep(_queue("a:1b", "b:1b"), world.settings, world.deps) == 0
    assert [r["status"] for r in sr.read_records(_sdir(world))] == ["stopped_for_memory",
                                                                   "completed"]


def test_dry_run_touches_nothing(world, capsys):
    world.names["b:1b"] = {"digest": "d", "size": 1}
    sr.mark_done(_sdir(world), "c:1b")
    before = sorted(os.listdir(_sdir(world)))
    sweep.dry_run(_queue("a:1b", "b:1b", "c:1b"), world.settings, world.deps)
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 3
    assert "a:1b" in out[0] and "to pull" in out[0]
    assert "b:1b" in out[1] and "installed" in out[1]
    assert "c:1b" in out[2] and "done" in out[2]
    assert world.calls == [] and sorted(os.listdir(_sdir(world))) == before


@pytest.mark.parametrize("bad", ["", "S1", "a b", "../x", "-a", "a_b"])
def test_bad_sweep_id_refused(bad, capsys):
    assert sweep.main(["--sweep-id=" + bad, "--dry-run"]) == 2
    assert "sweep-id" in capsys.readouterr().err


# ---- fixes from the independent review --------------------------------------

def test_pull_that_adds_no_new_name_claims_nothing_and_deletes_nothing(tmp_path):
    # the user has qwen3:8b; the queue spells it another way; Ollama's pull is a no-op
    world = World(tmp_path, installed=["qwen3:8b"])
    world.deps.pull = lambda tag: world.calls.append(("pull", tag))
    rec = world.run("library/qwen3:8b")
    assert rec["status"] == "pull_failed" and "installed list" in rec["reason"]
    assert rec["pulled_by_sweep"] is False and rec["deleted"] is False
    assert "delete" not in world.kinds() and "qwen3:8b" in world.names


def test_prior_claim_needs_the_same_digest(tmp_path):
    world = World(tmp_path, installed=["a:1b"])
    prior = sr.new_record("a:1b")
    prior.update(pulled_by_sweep=True, deleted=False, digest="some-other-digest")
    rec = world.run("a:1b", attempt=2, prior=prior)
    assert rec["pulled_by_sweep"] is False and rec["deleted"] is False
    assert "a:1b" in world.names and "delete" not in world.kinds()


def test_batch_that_cannot_be_stopped_keeps_the_model_and_says_so(world):
    world.batch_kwargs[0] = {"polls": 500, "interrupt_at": 2}
    world.deps.stop_batch = lambda plan: {"killed": False, "regrade_exit": None,
                                          "regrade_output": "access denied"}
    rec = world.run("a:1b")
    assert rec["status"] == "stopped" and rec["batch_left_running"] is True
    assert "could not be stopped" in rec["reason"] and "left installed" in rec["reason"]
    assert world.kinds() == ["pull", "load_check", "batch"]
    assert rec["deleted"] is False and "a:1b" in world.names


def test_stop_waits_for_a_plan_with_a_pid_and_never_stops_without_one(world):
    world.batch_kwargs[0] = {"polls": 500, "interrupt_at": 2}
    world.deps.read_plan = lambda out_dir: {"batch_id": "x", "pid": None}
    rec = world.run("a:1b")
    assert "stop" not in world.kinds() and rec["batch_left_running"] is True
    assert "delete" not in world.kinds() and "unload" not in world.kinds()


def test_sweep_stops_when_a_batch_was_left_running(world):
    world.batch_kwargs[0] = {"polls": 500, "on_poll": lambda n: setattr(world, "free_now", GB)}
    world.deps.stop_batch = lambda plan: {"killed": False, "regrade_exit": None,
                                          "regrade_output": "access denied"}
    assert sweep.run_sweep(_queue("a:1b", "b:1b"), world.settings, world.deps) == 4
    doc = json.load(open(os.path.join(_sdir(world), "sweep.json")))
    assert "still be running" in doc["stopped_reason"]
    assert ("pull", "b:1b") not in world.calls


def test_batch_with_no_valid_run_is_batch_failed(world):
    world.batch_kwargs[0] = {"invalid": 18}
    rec = world.run("a:1b")
    assert rec["status"] == "batch_failed" and "no valid run" in rec["reason"]
    assert world.kinds().count("batch") == 1


def test_probe_error_while_watching_stops_the_batch(world):
    state = {"n": 0}

    def free():
        state["n"] += 1
        if state["n"] == 4:
            raise sweep_probe.ProbeError("GlobalMemoryStatusEx failed: error 5")
        return 20 * GB
    world.deps.free_memory = free
    world.batch_kwargs[0] = {"polls": 50}
    rec = world.run("a:1b")
    assert rec["status"] == "batch_failed" and "GlobalMemoryStatusEx" in rec["reason"]
    assert world.kinds() == ["pull", "load_check", "batch", "stop", "unload", "delete"]


def test_batch_that_cannot_start_is_batch_failed_and_cleaned_up(world):
    def refuse(command, console):
        raise OSError("cannot create process")
    world.deps.start_batch = refuse
    rec = world.run("a:1b")
    assert rec["status"] == "batch_failed" and "cannot create process" in rec["reason"]
    assert world.kinds() == ["pull", "load_check", "unload", "delete"]


def test_batch_ids_that_would_be_too_long_are_refused_before_anything_runs():
    assert sweep.batch_id_problem("s1", ["mistral-nemo:12b"], [0.1, 0.3, 0.7]) is None
    problem = sweep.batch_id_problem("a" * 38, ["mistral-nemo:12b"], [0.1])
    assert problem and "64" in problem and "mistral-nemo:12b" in problem
