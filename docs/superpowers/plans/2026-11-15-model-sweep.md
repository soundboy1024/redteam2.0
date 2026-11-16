# Model Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One command that takes a queue of Ollama model tags and, for each, pulls it, checks it loads, runs the scenarios through `run_eval.py`, confirms the results, deletes it, and records what happened.

**Architecture:** Three small root-level modules. `sweep_record.py` holds the queue file, the fit record and the done markers. `sweep_probe.py` holds every call to Ollama and to the operating system. `sweep.py` holds the per-model steps, the loop and the CLI; it receives its probes and process starters as arguments so tests download nothing. Batches are only ever the `run_eval.py` command run as a separate process.

**Tech Stack:** Python, `requests`, `pyyaml`, `ctypes` for free memory. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-15-model-sweep-design.md`

## Global Constraints

- No import of `harness/`, `traps/` or `telemetry/` from the three sweep modules. `sweep.py` may import `batch_plan` and `dashboard.control` (for `stop_batch`).
- No bare `except`, no `except Exception: pass`. Every failure has a reason string in the record and a log line.
- A process is stopped only through the pid in a batch's own `batch.json` (`control.stop_batch`). Nothing is killed by name; no port is swept.
- A model that was installed before the sweep started is never deleted.
- A done marker is written only after every step for that model succeeded.
- The record is written (JSON and markdown) before any delete and after every model.
- Ollama host comes from `config.yaml` (`ollama_host`); `num_ctx` from `config.yaml`.
- Floors come from `sweep_queue.yaml`: `min_free_disk_gb` 30, `min_free_memory_gb` 6, `stop_free_memory_gb` 2.
- Commits: none unless the director asks (standing instruction). Tasks end with a test run, not a commit.

## Rulings made while planning

- Ruling: the record holds system free memory at the start and end of each batch, not the runner process's own size. Reading another process's memory needs `psutil` or more `ctypes`; free memory shows the same growth. Cost if wrong: the growth figure includes other programs' use.
- Ruling: pull and delete go through Ollama's HTTP API (`/api/pull`, `/api/delete`), not the `ollama` command. Same effect, one fewer thing to parse.
- Ruling: status `stopped` (Ctrl+C) is added to the spec's status list.

## Review Focus

1. A model present before the sweep is deleted (the tag is installed under a different spelling, for example `llama3.2` against `llama3.2:latest`). Expected: never deleted.
2. A batch that ends with exit code 0 but fewer recorded runs than planned. Expected: `batch_failed`, no marker.
3. A restart after a crash mid-model: the batch id of the unfinished model already exists. Expected: the retry uses a new batch id and does not fail on "already exists".
4. Ollama unreachable in the middle of a model. Expected: a record with the reason, and the sweep stops after three such models in a row.
5. A queue file with a duplicate tag or a tag that turns into the same slug as another. Expected: refused at load with a message.

---

### Task 1: Queue, record and markers (`sweep_record.py`)

**Files:** Create `sweep_record.py`, `sweep_queue.yaml`, `tests/test_sweep_record.py`.

**Interfaces (produces):**
- `class QueueError(ValueError)`
- `load_queue(path: str) -> dict` returning `{"models": [str], "min_free_disk_gb": float, "min_free_memory_gb": float, "stop_free_memory_gb": float}`. Refuses: missing file, missing key, empty or non-list `models`, non-string or blank tag, duplicate tag, two tags with the same `slug`, a floor that is not a positive number, `stop_free_memory_gb >= min_free_memory_gb`.
- `slug(tag: str) -> str`: lower case, every character outside `a-z0-9` becomes `-`, runs of `-` collapsed, ends stripped (`qwen2.5:7b` -> `qwen2-5-7b`).
- `STATUSES = ("completed", "does_not_fit", "pull_failed", "load_failed", "batch_failed", "stopped_for_memory", "stopped")`
- `new_record(tag: str) -> dict` with every field of the spec's fit record set to `None`, `tag` set, `batches` an empty list, `attempt` 1.
- `sweep_dir(results_dir: str, sweep_id: str) -> str` (`<results_dir>/_sweep/<sweep_id>`)
- `is_done(sdir: str, tag: str) -> bool`, `mark_done(sdir: str, tag: str) -> None` (file `done/<slug>.done`)
- `read_records(sdir: str) -> list[dict]` (empty list when `sweep.json` is absent; a file that is not valid JSON raises `ValueError` naming the path)
- `write_records(sdir: str, sweep_id: str, records: list[dict]) -> None`: writes `sweep.json` (`{"sweep_id", "updated_at", "limitation", "records"}`) through a temp file and `os.replace`, and `sweep.md` (one table row per record: tag, status, reason, backend, GPU share, size in memory GB, tokens/s, lowest free memory GB, runs valid/invalid, deleted) followed by the limitations text (exact-match canaries; the two prompt-pointer scenarios are not comparable with the two indirect-injection scenarios).
- `upsert(records: list[dict], record: dict) -> list[dict]`: replaces the record with the same tag or appends.

- [ ] Step 1: tests in `tests/test_sweep_record.py`: `test_slug` (`"qwen2.5:7b"` -> `"qwen2-5-7b"`, `"hf.co/A/B:Q4_K_M"` -> `"hf-co-a-b-q4-k-m"`); `test_load_queue_reads_the_shipped_file` (13 models, floors 30/6/2); parametrised `test_load_queue_refuses` over each refusal above with `pytest.raises(QueueError, match=...)`; `test_marker_roundtrip`; `test_write_and_read_records` (JSON round trip, `sweep.md` contains the tag, the status and "exact string match"); `test_upsert_replaces_same_tag`; `test_read_records_bad_json_names_the_file`.
- [ ] Step 2: run `.venv\Scripts\python.exe -m pytest -q tests/test_sweep_record.py`. Expected: fails on import.
- [ ] Step 3: write `sweep_record.py` and `sweep_queue.yaml` (the 13 tags and three floors from the spec).
- [ ] Step 4: run the same command. Expected: all pass.

### Task 2: Probes (`sweep_probe.py`)

**Files:** Create `sweep_probe.py`, `tests/test_sweep_probe.py`.

**Interfaces (produces):** every function takes `host: str` first where it talks to Ollama and uses a `requests.Session` with `trust_env = False`.
- `class ProbeError(RuntimeError)`: raised for a connection error, timeout, non-200 status, non-JSON body or an `{"error": ...}` body, with the endpoint and the reason in the message.
- `installed(host) -> dict[str, dict]`: `GET /api/tags`, name -> `{"digest", "size"}`.
- `is_installed(tag: str, names) -> bool`: true when `tag` is in `names`, or `tag` has no `:` and `tag + ":latest"` is in `names`, or `tag` ends in `:latest` and the bare name is in `names`.
- `loaded(host) -> list[dict]`: `GET /api/ps`, each `{"name", "size", "size_vram"}`.
- `pull(host, tag, timeout_s=7200) -> None`: `POST /api/pull` `{"model": tag, "stream": false}`; success only when the body's `status` is `"success"`.
- `load_check(host, tag, num_ctx, timeout_s=600) -> dict`: `POST /api/chat` with one user message "Reply with the word ok.", `stream` false, `options` `{"num_ctx": num_ctx, "num_predict": 16}`; returns `{"tokens_per_s": eval_count / (eval_duration / 1e9) or None when either is missing or zero}`.
- `unload(host, tag, wait_s=120, sleep=time.sleep) -> bool`: `POST /api/generate` `{"model": tag, "keep_alive": 0}`, then polls `loaded` every 2 s until the tag is gone; false if still loaded after `wait_s`.
- `delete(host, tag) -> None`: `DELETE /api/delete` `{"model": tag}`.
- `free_memory_bytes() -> int`: `GlobalMemoryStatusEx` through `ctypes` (`ullAvailPhys`); raises `ProbeError` if the call fails.
- `free_disk_bytes(path: str) -> int`: `shutil.disk_usage(path).free`.
- `backend_from_log(log_path: str, since_offset: int) -> str | None`: reads the file from `since_offset`, returns the last `library=<word>` value found (for example `Vulkan`, `ROCm`, `cpu`), or `None` when the file is missing or has no such line (logged at WARNING).
- `log_size(log_path: str) -> int`: file size, 0 when missing.
- `DEFAULT_LOG = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Ollama", "server.log")`

- [ ] Step 1: tests with a fake session (monkeypatch `sweep_probe._session`): `installed` and `loaded` parse the shapes Ollama returns; parametrised `test_is_installed` (`("llama3.2", {"llama3.2:latest"})` true, `("llama3.2:latest", {"llama3.2"})` true, `("llama3.2:1b", {"llama3.2:latest"})` false); `pull` raises `ProbeError` on status 404, on `{"error": "x"}` and on a body without `"status": "success"`; `load_check` computes 20.0 tokens/s from `eval_count` 40 and `eval_duration` 2e9 and gives `None` when `eval_duration` is 0; `unload` returns false when the tag never leaves `loaded`; `backend_from_log` returns the last library after the offset and `None` for a missing file; `free_memory_bytes() > 0` and `free_disk_bytes(".") > 0` (real calls); a connection error becomes `ProbeError` naming the endpoint.
- [ ] Step 2: run `.venv\Scripts\python.exe -m pytest -q tests/test_sweep_probe.py`. Expected: fails on import.
- [ ] Step 3: write `sweep_probe.py`.
- [ ] Step 4: run the same command. Expected: all pass.

### Task 3: One model (`sweep.py`, `run_model`)

**Files:** Create `sweep.py`, `tests/test_sweep.py`.

**Interfaces:**
- Consumes: everything Task 1 and Task 2 produce; `batch_plan.read_plan(out_dir)`; `dashboard.control.stop_batch(plan, cwd, python_exe, host, port, config_path)`.
- Produces:
  - `@dataclass Deps` with callables `installed, loaded, pull, load_check, unload, delete, free_memory, free_disk, backend, log_size, start_batch, stop_batch, read_plan, sleep`. `start_batch(command: list[str], console_log: str) -> process` (an object with `poll()`, `wait()` and `returncode`). `real_deps(cfg, root) -> Deps` wires the real ones.
  - `@dataclass Settings`: `sweep_id, root, python_exe, config_path, results_dir, ollama_host, num_ctx, temperatures, listener_host, listener_port, min_free_disk, min_free_memory, stop_free_memory` (bytes), `watch_s = 30`.
  - `class Preflight(RuntimeError)`: the sweep must stop.
  - `preflight(s: Settings, d: Deps, port_open) -> None`: raises `Preflight` with the reason when port open, a model is loaded, free disk under the floor or free memory under the floor.
  - `batch_id(sweep_id, tag, temperature, attempt) -> str`: `sweep-<sweep_id>-<slug>-t<temperature with the dot removed>`, plus `-r<attempt>` when attempt is above 1.
  - `verify_batch(s, d, bid, exit_code) -> tuple[bool, str, int, int]`: (ok, reason, valid, invalid). Not ok when exit code is not 0, `results.json` is missing, the plan is missing, `aborted` is not false, `ended_at` is empty, or the number of rows in `results.json["results"]` differs from `planned_runs`.
  - `run_model(tag, s, d, attempt=1) -> dict`: the record. Steps 3 to 9 of the spec. Statuses as in `sweep_record.STATUSES`. Sets `pulled_by_sweep`, `deleted`, `reason`, `backend`, `gpu_share` (`size_vram / size`), `size_in_memory`, `tokens_per_s`, `free_memory_after_load`, `lowest_free_memory`, `batches` (each `{"batch_id", "temperature", "exit_code", "ok", "reason", "valid", "invalid", "free_memory_start", "free_memory_end"}`), `seconds`.
  - Behaviour fixed here: a failed batch stops the remaining temperatures for that model; the model is unloaded after every batch and before the delete; delete happens only when `pulled_by_sweep` is true, whatever the status; a failed unload or delete is recorded in `reason` and makes the status `batch_failed` unless a worse one is already set; `ProbeError` during pull gives `pull_failed`, during the load check `load_failed`; `KeyboardInterrupt` during a batch stops it through `stop_batch`, sets `stopped`, and is re-raised after the record is filled in (the record is attached to the exception as `.record`).

- [ ] Step 1: tests in `tests/test_sweep.py` with a `FakeDeps` builder (in-memory installed set, scripted free-memory values, fake processes that write a `results.json` and `batch.json` into `tmp_path`): `test_completed_model_is_pulled_run_three_times_and_deleted` (three batch ids, call order pull, load_check, then per batch start/unload, then delete; status `completed`); `test_preinstalled_model_is_never_deleted` (also with the `llama3.2` / `llama3.2:latest` spelling); `test_pull_failure_recorded_and_nothing_deleted`; `test_load_failure_deletes_what_it_pulled`; `test_does_not_fit_runs_no_batch` (free memory after load under 6 GB); `test_memory_watch_stops_the_batch` (free memory drops under 2 GB on the second poll; `stop_batch` called once with that batch's plan; status `stopped_for_memory`; no further batches); `test_short_batch_is_batch_failed` (exit 0, 17 rows, planned 18); `test_aborted_batch_is_batch_failed`; `test_batch_id_retry_suffix` (`batch_id("s1", "qwen2.5:7b", 0.1, 1) == "sweep-s1-qwen2-5-7b-t01"`, attempt 2 ends `-r2`); `test_preflight_reasons` (four cases); `test_ctrl_c_stops_batch_and_carries_record`; `test_unload_failure_is_recorded`.
- [ ] Step 2: run `.venv\Scripts\python.exe -m pytest -q tests/test_sweep.py`. Expected: fails on import.
- [ ] Step 3: write `run_model` and its helpers in `sweep.py`.
- [ ] Step 4: run the same command. Expected: all pass.

### Task 4: The loop and the command line (`sweep.py`, `run_sweep`, `main`)

**Files:** Modify `sweep.py`, `tests/test_sweep.py`.

**Interfaces (produces):**
- `run_sweep(queue: dict, s: Settings, d: Deps, port_open) -> int`: for each tag: skip when `is_done`; `preflight` (a `Preflight` stops the sweep, exit code 2, reason logged and written to `sweep.json` as `stopped_reason`); `attempt` is one more than the attempt in an existing record for that tag; `run_model`; `upsert` and `write_records`; `mark_done` only when status is `completed`. Three models in a row with `pull_failed` or `load_failed` stop the sweep with exit code 3. `KeyboardInterrupt` writes the carried record and returns 130. Returns 0 when the queue is exhausted, even if some models failed (their records say so).
- `main(argv) -> int`: `--sweep-id` (required, same character rule as `slug` output), `--queue` (default `sweep_queue.yaml`), `--config` (default `config.yaml`), `--dry-run` (prints, per tag: done or to do, installed or to pull; touches nothing). Usage line in the module docstring: `.venv\Scripts\python.exe sweep.py --sweep-id <name>`.
- Logging to the console and to `results/_sweep/<sweep_id>/sweep.log`.

- [ ] Step 1: tests: `test_sweep_skips_done_models_on_restart`; `test_failed_model_is_retried_with_a_new_batch_id` (second run's batch ids end `-r2`); `test_preflight_failure_stops_before_the_next_model` (exit 2, later tags untouched); `test_three_pull_failures_in_a_row_stop_the_sweep` (exit 3, fourth tag untouched); `test_two_failures_then_a_success_resets_the_count`; `test_record_written_before_delete` (the fake `delete` asserts the tag is already in `sweep.json`); `test_ctrl_c_returns_130_and_leaves_no_marker`; `test_dry_run_touches_nothing`; `test_bad_sweep_id_refused`.
- [ ] Step 2: run `.venv\Scripts\python.exe -m pytest -q tests/test_sweep.py`. Expected: the new tests fail.
- [ ] Step 3: write `run_sweep`, `real_deps`, `main`.
- [ ] Step 4: run the same command. Expected: all pass. Then `.venv\Scripts\python.exe sweep.py --sweep-id dryrun --dry-run`. Expected: 13 lines, exit 0, no `results/_sweep/dryrun` folder.

### Task 5: Specification, rule check and Gate 5

**Files:** Modify `CLAUDE.md`, `BACKLOG.md`, `scripts/check_rules.py`, `.claude/skills/run-gate/SKILL.md`. Create `gates/gate5.py`, `tests/test_gate5.py`. Test: existing `tests/test_check_rules.py` if present.

- [ ] Step 1: `CLAUDE.md`: add section 4.9 "Model sweep" (steps, delete rule, stop conditions, record fields, statuses, the three floors); add `sweep.py`, `sweep_record.py`, `sweep_probe.py`, `sweep_queue.yaml` to section 5; add "Phase 5. Model sweep" and Gate 5 to section 6 (a sweep of two entries: one small real model that is not installed, and one tag that does not exist; evidence: the real model `completed` and deleted, the bad tag `pull_failed`, a second start skips the finished model; director gate); in section 2 rule 5 name Gate 5 with gates 3 and 4. Remove the sweep line from `BACKLOG.md`.
- [ ] Step 2: test that `scripts/check_rules.py` reports a violation for a `sweep*.py` file at the root that imports `harness`, `traps` or `telemetry`; run it; expected fail; add the rule; expected pass; `.venv\Scripts\python.exe scripts\check_rules.py` exits 0.
- [ ] Step 3: `gates/gate5.py --sweep-id <id>`: reads `results/_sweep/<id>/sweep.json` and the batch folders (starts nothing, like Gate 4), checks the evidence listed in Step 1 plus: every batch of the completed model verifies, the model is absent from a record field `installed_after` (the sweep records the installed list after its delete), and the done marker exists only for the completed model. Prints the records, writes `gates/evidence/gate5.txt` and `gate5.json`, exits 0 or 1. Tests in `tests/test_gate5.py` build a passing and three failing sweep folders in `tmp_path`.
- [ ] Step 4: full suite `.venv\Scripts\python.exe -m pytest -q`. Expected: all pass. Gate 5 itself needs a real sweep (a download and three batches) and is run only on the director's word.
