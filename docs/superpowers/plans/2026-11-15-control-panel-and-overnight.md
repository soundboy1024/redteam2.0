# Control Panel, Inspector and Overnight Runs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A three-page Streamlit app (Run, Results, Inspect a run) that starts and watches batches, a regrade command, per-run stored results, overnight local and hosted batches, and Gate 4 evidence.

**Architecture:** `run_eval.py` stays the only way a batch runs. It gains a plan file (`batch.json`), a result row stored as each run finishes, `--plan` and `--regrade`. The dashboard reads the run log and listener database read-only and starts or stops `run_eval.py` as a separate process identified by the pid in `batch.json`.

**Tech Stack:** Python 3, Streamlit 1.67 (`st.fragment(run_every=...)`, `streamlit.testing.v1.AppTest`), SQLite, pytest. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-15-control-panel-and-overnight-design.md`

## Global Constraints

- Branch `phase4`, cut from `post-gate3`. No push, no merge into `main`.
- No change to tripwire logic, completion checks, the parser, the tools, the scenarios or the fixtures. `telemetry/grader.py` may be refactored in Task 2 only, with grade output unchanged.
- After Task 4 is committed, `harness/`, `telemetry/grader.py`, `traps/`, `batch_results.py` and `run_eval.py` are frozen until Task 11 is done. Record the commit hash each batch ran at.
- `dashboard/` never imports `harness`. `harness/` never imports `traps` or `telemetry`.
- The dashboard never grades and never shows, logs or stores an API key value. Model text is rendered with `st.code` or `st.text`, never `unsafe_allow_html`.
- No bare `except`, no `except Exception: pass`. Every failure is logged or raised.
- One batch at a time (listener port 8999). A process is only ever killed by the pid recorded in its own `batch.json`; never by name, never by sweeping a port (the dashboard's own launcher port 8503 excepted, per the launcher convention).
- Dashboard port 8503. Launcher uses `.venv\Scripts\python.exe -m streamlit`.
- Stored result rows are never overwritten.
- No Cerebras call. Groq: one model, 18 runs first.
- Every test command is `.venv/Scripts/python.exe -m pytest ...`. After every task: full suite and `.venv/Scripts/python.exe scripts/check_rules.py` must pass before the commit.
- Commit messages end with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.

## Review Focus

1. A batch killed between "run recorded" and "result stored": the Run page must show that run as "recorded, not graded yet" and regrade must fill it in. Test in Task 3 (`test_regrade_fills_only_missing_rows`).
2. `batch.json` missing or unreadable (every batch before this change): every page must still list the batch, with planned count "unknown". Tests in Task 5 (`test_progress_without_plan_file`) and Task 7 (AppTest against a fixture with no `batch.json`).
3. Result rows without `attempted_*` fields (written before the attempted-calls change): Results and Inspect must render "not recorded", not raise. Test in Task 5 (`test_matrix_tolerates_old_result_rows`).
4. Start pressed while port 8999 is busy or another batch is alive: no second process, and the page says why. Test in Task 6 (`test_start_refused_when_port_busy`).
5. A temperature of `None` (hosted models without temperature) in grouping, sorting and display: shown as "default", sorted last, never compared with a float. Test in Task 5 (`test_matrix_handles_default_temperature`).

## File map

| File | Responsibility |
|---|---|
| `CLAUDE.md` | New section 4.8, amended Phase 4, layout |
| `batch_plan.py` (new) | Build, write, read and finalise `batch.json` |
| `batch_results.py` | Grade-and-store one run; finish a batch from stored rows |
| `telemetry/grader.py` | `grade_logged_run` split out of `grade_batch` (no rule change) |
| `telemetry/logger.py` | `existing_batch`, `read_result_rows`, `read_step_run_ids` |
| `run_eval.py` | Per-run storing, `batch.json`, `--plan`, `--regrade` |
| `dashboard/data.py` (new) | Read-only queries: batches, progress, matrix, run detail |
| `dashboard/control.py` (new) | Command building, plan preview, start, stop, liveness, key status |
| `dashboard/app.py` (new) | The three pages |
| `run_dashboard.bat` (new) | Launcher, port 8503 |
| `gates/gate4.py` (new) | Gate 4 evidence |
| `scripts/check_rules.py` | Rule: `dashboard/` must not import `harness` |

---

### Task 1: Spec text and branch

**Files:** Modify `CLAUDE.md`, `BACKLOG.md`.

- [ ] **Step 1:** `git switch -c phase4`. Commit the design doc and this plan (`docs: control panel design and plan`).
- [ ] **Step 2:** In `CLAUDE.md` add section **4.8 Control panel (dashboard/)** stating, in the project's plain style: the three pages; the Run page starts the same `run_eval.py` command and shows it; one batch at a time; progress read from the run log and listener database read-only; the dashboard never grades, never shows a key, never imports `harness/`; Stop kills only the pid in the batch's `batch.json` and then regrades; `batch.json` contents; a result row is stored as each run finishes and regrade completes but never overwrites; `--plan` and `--regrade`. Amend Phase 4 ("One Streamlit page, dark theme, two views") to three views, and Gate 4 to "a fresh batch started from the Run page". Add `batch_plan.py`, `dashboard/data.py`, `dashboard/control.py`, `run_dashboard.bat`, `gates/` to section 5.
- [ ] **Step 3:** In `BACKLOG.md` remove the Tier 1b line "Regrade command" (now in scope) and add under Tier 4: "More hosted providers: Mistral (free tier, no card) and Gemini through an AI Studio key. Needs a 4.7 entry per provider."
- [ ] **Step 4:** Run the full suite and `check_rules.py`. Commit `docs: control panel in scope (CLAUDE.md 4.8), backlog update`.

### Task 2: Per-run grading and stored-row reads

**Files:** Modify `telemetry/grader.py`, `telemetry/logger.py`, `batch_results.py`. Test: `tests/test_grader.py`, `tests/test_run_log.py`, `tests/test_report.py` or `tests/test_run_eval.py` (wherever `write_batch_results` is tested today).

**Interfaces (produces):**
- `telemetry.grader.grade_logged_run(db_path: str, listener_db_path: str, run: dict, scenarios_by_id: dict, canaries: list[dict]) -> dict` — the body of the `grade_batch` loop, including its `KeyError` for an unknown scenario. `grade_batch` calls it.
- `telemetry.logger.read_result_rows(db_path: str, batch_id: str) -> list[dict]` — each stored row's `result_json` decoded, in rowid order.
- `telemetry.logger.read_step_run_ids(out_dir: str) -> list[str]` — distinct `run_id` values in `<out_dir>/steps.jsonl`, in first-seen order; raises `ValueError` naming the line number on a malformed line.
- `batch_results.grade_and_store_run(cfg: dict, batch_log, scenarios: list[dict], run_id: str) -> dict` — grades the one recorded run with `grade_logged_run`, stores it with `log_result`, returns the row. A store failure raises `LogWriteError`. A run that already has a stored row raises `ValueError` (from `log_result`'s once-only insert) wrapped as `LogWriteError`.
- `batch_results.write_batch_results(cfg, batch_log, scenarios, meta) -> list[dict]` — same signature, new behaviour: stored rows are read and kept; only runs without a stored row are graded; files are written from the merged list in run order (files first, as today); then the newly graded rows are stored. Returns the merged list.

- [ ] **Step 1: Failing tests.**
  - `test_grade_logged_run_equals_grade_batch_row`: for a logged two-run batch, `[grade_logged_run(...) for run in read_runs(...)] == grade_batch(...)`.
  - `test_read_result_rows_round_trip`: a row stored with `log_result` comes back equal to the dict that was stored (after the logger's own sanitising), including `attempted_calls`.
  - `test_read_step_run_ids_order_and_bad_line`.
  - `test_grade_and_store_run_stores_one_row` and `test_grade_and_store_run_twice_raises_log_write_error`.
  - `test_write_batch_results_keeps_stored_rows`: store run A's row, then alter A's logged `final_response` in the database, call `write_batch_results`; A's returned row and `results.json` entry equal the stored row, B is newly graded, and the `results` table has exactly two rows.
  - `test_per_run_and_batch_end_grades_identical`: batch 1 graded only at the end, batch 2 (same scripted replies) graded per run; rows are equal apart from `run_id`, `batch_id` and timestamps.
- [ ] **Step 2:** Run them; expect failures for missing names.
- [ ] **Step 3:** Implement the five interfaces.
- [ ] **Step 4:** Full suite and `check_rules.py` pass.
- [ ] **Step 5:** Commit `feat(results): grade and store one run; batch end keeps stored rows`.

### Task 3: batch.json, per-run storing in run_eval, --plan, --regrade

**Files:** Create `batch_plan.py`. Modify `run_eval.py`, `telemetry/logger.py`. Test: `tests/test_batch_plan.py` (new), `tests/test_run_eval.py`, `tests/test_run_log.py`.

**Interfaces (produces):**
- `batch_plan.PLAN_FILE = "batch.json"`.
- `batch_plan.build_plan(batch_id: str, models: list, scenario_ids: list, temperatures: list, n_runs: int, telemetry: bool, temps_per_model: dict[str, list], command: list[str] | None) -> dict` with keys `batch_id, models, scenario_ids, temperatures, n_runs, telemetry_enabled, temps_per_model, planned_runs, command, pid, started_at, ended_at, aborted, abort_reason`. `planned_runs = sum(len(temps_per_model[m]) for m in models) * len(scenario_ids) * n_runs`. `pid`, `started_at`, `ended_at`, `aborted`, `abort_reason` start as `None`.
- `batch_plan.write_plan(out_dir: str, plan: dict) -> str` (atomic: temp file then `os.replace`), `batch_plan.read_plan(out_dir: str) -> dict | None` (None if the file is absent; `ValueError` if present but not a JSON object), `batch_plan.finalise_plan(out_dir: str, ended_at: str, aborted: bool, abort_reason: str | None) -> None`.
- `telemetry.logger.existing_batch(db_path: str, results_dir: str, batch_id: str) -> BatchLog` — `ValueError` for a bad id, a missing folder, or a run log with the wrong schema version. Creates nothing.
- `run_eval.py --plan`: with the usual selection flags, prints the plan as one JSON object (pid and times null, `command` the argv it would run without `--plan`) and exits 0. Opens no batch, starts no listener. All the usual validation errors (unknown model, missing key, bad temperatures) still exit 1 with their message.
- `run_eval.py --regrade <batch_id>`: prints `summary: <path>` and one line per run like a normal batch; exit 0. Exit 1 with a message for: unknown batch folder, no recorded runs, or "every run of batch X already has a stored result and its files exist".
- `run_eval.regrade(cfg: dict, batch_id: str, scenarios: list[dict]) -> dict` returning `{"batch_id", "out_dir", "results", "orphan_run_ids"}`.

**Behaviour to implement:**
- `prepare_batch` writes `batch.json` right after `open_batch`; `execute_batch` sets `pid` (`os.getpid()`) and `started_at` once the listener is up, and calls `finalise_plan` on every exit path that reaches the results step. `_remove_empty_batch` must also remove `batch.json`.
- In `_run_all`, after `record_run(rec)`: `grade_and_store_run(cfg, batch_log, prep.scenarios, rec["run_id"])`. A `LogWriteError` propagates and aborts the batch as today.
- Regrade meta: from `batch.json` when present; otherwise `models` and `scenario_ids` are the distinct values in the run rows in first-seen order, `temperatures` the distinct run temperatures, `n_runs` the highest `repetition_index + 1`, `telemetry_enabled` from the first run, `started_at`/`ended_at` the first run's start and last run's end. `aborted` is False only when `batch.json` exists and `planned_runs` equals the recorded run count; otherwise True with `abort_reason` "regraded after the batch stopped early" (plan present) or "regraded; planned run count unknown" (no plan). `hosted_models` and `models_without_temperature` computed as `execute_batch` does.
- Orphans: `read_step_run_ids(out_dir)` minus recorded run ids. Each is added to the meta as `orphan_run_ids` and written into `summary.md` notes as "steps logged for run <id> but the run was never recorded (cut off mid-run); it is in no cell". If `write_summary_md` has no hook for batch-level notes, add an optional `batch_notes: list[str] | None = None` parameter printed under "## Notes"; existing callers unchanged.

- [ ] **Step 1: Failing tests.**
  - `test_build_plan_counts_runs`: 2 models with 3 and 1 temperatures, 6 scenarios, n_runs 3 gives `planned_runs == 72`.
  - `test_write_read_finalise_plan_round_trip`; `test_read_plan_absent_is_none`; `test_read_plan_not_object_raises`.
  - `test_existing_batch_errors` (bad id, missing folder) and that it creates no file.
  - `test_batch_writes_plan_file_with_pid_and_end`: after a scripted batch, `batch.json` has `planned_runs`, an int `pid`, `ended_at` set, `aborted` False.
  - `test_result_row_stored_after_each_run`: a chat function that, at the start of run 2, reads `read_result_rows` and asserts run 1's row is already there.
  - `test_plan_flag_prints_json_and_opens_nothing`: exit 0, stdout parses to an object with `planned_runs`, no folder under `results_dir`, port never opened (listener start patched to fail the test if called).
  - `test_plan_flag_missing_key_exits_1`.
  - `test_regrade_fills_only_missing_rows`: batch of 3 where run 3's stored row is deleted and `results.json` removed; regrade stores exactly one new row, leaves the other two byte-identical in the table, and writes the files.
  - `test_regrade_refuses_complete_batch`; `test_regrade_unknown_batch_exits_1`.
  - `test_regrade_without_plan_file_marks_aborted_and_names_orphans`: delete `batch.json`, append a step line for an unrecorded run id to `steps.jsonl`; summary says aborted with "planned run count unknown" and names the orphan.
  - `test_failed_listener_start_removes_plan_file`.
- [ ] **Step 2:** Run; expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Full suite and `check_rules.py` pass.
- [ ] **Step 5:** Commit `feat(batch): batch.json, per-run stored results, --plan and --regrade`.

### Task 4: Regrade the stopped batch, re-run Gate 3, freeze

- [ ] **Step 1:** `.venv/Scripts/python.exe run_eval.py --regrade qwen7b-all6-3temps`. Expected: 33 result lines, summary marked aborted, one orphan run id named. Check `SELECT COUNT(*) FROM results WHERE batch_id='qwen7b-all6-3temps'` is 33.
- [ ] **Step 2:** Follow the `run-gate` skill for Gates 1, 2 and 3 (rule checks first). All three must print PASS. A failure stops the plan here.
- [ ] **Step 3:** Add the local models to `config.yaml` `models`: `llama3.1:latest`, `gemma2:9b-instruct-q4_K_M`, `phi4-mini:latest`, `ministral-3:8b`. Run `tests/test_config.py`.
- [ ] **Step 4:** Commit evidence and config (`chore: gate evidence at phase4, local models in config`). Record this commit hash as the **freeze hash**.

### Task 5: Start the local batches (background), then dashboard data module

The local batches run while Tasks 5 to 8 are built. One background shell command runs them in order; before each, free physical memory must be at least 8 GB or the chain stops and writes why to its log.

- [ ] **Step 1:** Write `scripts/overnight_local.ps1`: for each of `llama3.1:latest`, `gemma2:9b-instruct-q4_K_M`, `phi4-mini:latest`, `ministral-3:8b`, `llama3.2:3b`: check free memory (`Win32_OperatingSystem.FreePhysicalMemory` ≥ 8 GB, else write a line and exit 2); run `run_eval.py --models <m> --batch-id night-<short>-3temps`; console output to `results/_console/<batch_id>.log`. A non-zero exit from a batch is logged and the chain continues to the next model (batches are independent), except exit from the memory check. Start it in the background.
- [ ] **Step 2: Failing tests** in `tests/test_dashboard_data.py` against a temp run log built with the real logger functions:
  - `test_list_batches_newest_first_with_counts`: returns dicts `{batch_id, recorded_runs, stored_results, planned_runs, started_at, ended_at, aborted, models}`.
  - `test_progress_without_plan_file`: `planned_runs is None`, no exception.
  - `test_progress_names_current_run`: with steps logged for a run not yet recorded, `current` is `{scenario_id, model_name, temperature, repetition_index, last_steps}`.
  - `test_finished_runs_show_stored_cell_or_not_graded`.
  - `test_matrix_adds_batches_together`: two batches, same model/temperature/taxonomy, counts add; `included` lists both; an aborted one is flagged.
  - `test_matrix_handles_default_temperature`: a `None` temperature row is labelled "default" and sorted after numeric ones.
  - `test_matrix_tolerates_old_result_rows`: a stored row lacking `attempted_*` keys gives "not recorded" in the attempted column, no exception.
  - `test_run_detail_poison_step_and_full_tool_result`: `poison_step_index` is the first step with `poison_ingested` true (None if never); a 5000-character tool result comes back whole.
  - `test_run_detail_fixture_text_fallback`: when the model never read the poison file, its text is read from `fixtures_root` using the stored scenario entry.
  - `test_reads_do_not_write`: the database file's bytes are unchanged after every data function is called.
- [ ] **Step 3:** Implement `dashboard/data.py`:
  - `list_batches(db_path: str, results_dir: str) -> list[dict]`
  - `batch_progress(db_path: str, listener_db_path: str, results_dir: str, batch_id: str) -> dict` with keys `plan, recorded_runs, planned_runs, current, finished, listener_events` (`finished`: newest first; `listener_events`: last 20 raw rows for the batch's runs, each `{timestamp, method, path, classification, canary_ids}`).
  - `matrix(db_path: str, batch_ids: list[str]) -> dict` with keys `rows, included, totals`; `rows` built with `telemetry.report.build_matrix` over the stored rows of all chosen batches plus trajectory hashes from `batch_results.trajectory_hash`.
  - `run_detail(db_path: str, listener_db_path: str, fixtures_root: str, run_id: str) -> dict` with keys `result, inputs, steps, tool_events, listener_events, poison_step_index, poison_texts, telemetry_enabled`.
  - `LIMITATIONS: tuple[str, ...]` — reuse the limitation constants from `telemetry/report.py`; add the prompt-pointer note for `fake_system_error` and `authority_spoof` from `CLAUDE.md` 4.3.
  - All SQLite access through one helper that opens `file:<path>?mode=ro` with `uri=True`.
- [ ] **Step 4:** Tests pass; full suite; `check_rules.py`.
- [ ] **Step 5:** Commit `feat(dashboard): read-only data module`.

### Task 6: Dashboard control module

**Files:** Create `dashboard/control.py`, `dashboard/__init__.py`. Test: `tests/test_dashboard_control.py`. Modify `scripts/check_rules.py`, `tests/test_rules.py`.

**Interfaces (produces):**
- `build_command(python_exe: str, models: list[str], scenario_ids: list[str], temperatures: list[float], n_runs: int, batch_id: str, config_path: str = "config.yaml") -> list[str]`
- `preview_plan(command: list[str], cwd: str) -> tuple[dict | None, str | None]` — runs the command plus `--plan` (timeout 30 s); returns the plan, or `(None, message)` with run_eval's error text.
- `key_status(models: list[str], environ) -> dict[str, bool]` — per hosted model, whether its key variable is set. Provider-to-variable mapping is its own small constant here (`anthropic/` → `ANTHROPIC_API_KEY`, `groq/` → `GROQ_API_KEY`, `cerebras/` → `CEREBRAS_API_KEY`), with a test that it equals `harness.remote_client.PROVIDERS` key names (the test may import harness; the module may not).
- `batch_state(plan: dict | None, port_open: bool, has_results_files: bool) -> str` — one of `"running"`, `"finished"`, `"aborted"`, `"stopped_without_results"`, `"unknown"`. Running = plan has a pid, no `ended_at`, and the port is open.
- `start_batch(command: list[str], cwd: str, console_log: str, port_open: bool, running_batch: str | None) -> subprocess.Popen` — raises `StartRefused(reason)` if the port is open or a batch is running. Windows flags `CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`; stdout and stderr to `console_log`.
- `stop_batch(plan: dict, cwd: str, python_exe: str) -> dict` — `taskkill /PID <pid> /T /F` for the plan's pid only, waits for port 8999 to close (up to 15 s), then runs `run_eval.py --regrade <batch_id>`; returns `{"killed": bool, "regrade_exit": int, "regrade_output": str}`. Raises `ValueError` if the plan has no pid or already has `ended_at`.
- `scripts/check_rules.py`: files under `dashboard/` must not import `harness` (message `dashboard must not import harness`).

- [ ] **Step 1: Failing tests:** `test_build_command_exact_argv`; `test_preview_plan_ok_and_error` (subprocess patched); `test_key_status_never_returns_values`; `test_key_names_match_harness`; `test_batch_state_table` (parametrised over the five states); `test_start_refused_when_port_busy`; `test_start_refused_when_batch_running`; `test_stop_refuses_plan_without_pid`; `test_stop_kills_only_plan_pid_then_regrades` (subprocess patched; asserts the exact `taskkill` argv); `test_rules_flag_dashboard_importing_harness`.
- [ ] **Step 2:** Run; expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Full suite; `check_rules.py`.
- [ ] **Step 5:** Commit `feat(dashboard): control module (plan preview, start, stop)`.

### Task 7: The three pages and the launcher

**Files:** Create `dashboard/app.py`, `run_dashboard.bat`, `.streamlit/config.toml` (dark theme, `server.port = 8503`, `browser.gatherUsageStats = false`). Test: `tests/test_dashboard_app.py`.

- [ ] **Step 1: Failing tests** with `streamlit.testing.v1.AppTest.from_file("dashboard/app.py")`, the app reading its config path from env var `RT_DASHBOARD_CONFIG` (default `config.yaml`) so tests point it at a temp config and databases:
  - `test_run_page_renders_idle`: no exception; the command text contains `run_eval.py`; Start present.
  - `test_run_page_disables_hosted_model_without_key`.
  - `test_results_page_renders_matrix_and_limitations`: the exact-match canary limitation text is on the page.
  - `test_results_page_with_batch_lacking_plan_file`: no exception, "unknown" shown.
  - `test_inspect_page_renders_compromised_run`: tripwire names shown; model reply is in a code element.
  - `test_inspect_page_old_row_without_attempted_fields`: "not recorded" shown.
  - `test_no_page_uses_unsafe_html`: the source of `dashboard/app.py` does not contain `unsafe_allow_html`.
- [ ] **Step 2:** Implement `app.py`: sidebar radio for the three pages. Run page: model multiselect (hosted models without a key listed as disabled text, not selectable), scenario multiselect defaulting to all, temperature text input defaulting to the config list, runs-each number input, batch name defaulting to a UTC stamp, plan preview line, command in `st.code`, Start and Stop (Stop behind a confirm checkbox), and an `st.fragment(run_every=2)` progress block showing state, `recorded / planned`, the current run, latest steps, finished runs, and raw listener events under the caption "Raw listener events (not a grade)". Results page: batch multiselect, matrix table with counts and percentages, the extra columns from `summary.md`, included-batch list with aborted flags, limitations. Inspect page: batch then run selectors, two columns (poison text left, raw tool-call JSON right), marker on the poison step, tripwires, attempted calls in their own bordered block above the step list, `parse_reason` and `done_reason` per step, full tool results in expanders, entropy line chart only when `telemetry_enabled`.
- [ ] **Step 3:** `run_dashboard.bat` from the director's launcher template with `PORT=8503`, `PROJECT=redteam2.0 control panel`, `.venv` (this project's venv folder name), `dashboard\app.py`.
- [ ] **Step 4:** Tests pass; full suite; `check_rules.py`. Start the app once by hand and load each page in the browser; fix anything that raises.
- [ ] **Step 5:** Commit `feat(dashboard): Run, Results and Inspect pages; launcher on 8503`.

### Task 8: Hosted batches

Runs after the local chain from Task 5 has finished (port 8999 free). Keys are loaded into the launching process from the Windows user environment without being printed.

- [ ] **Step 1:** Write the cost estimate to `session_summary.md` before any hosted call: runs × up to 12 steps × measured prompt tokens per step (take the mean `prompt_token_count` and `token_count` from the qwen runs) × the current list price per model. State it as an upper bound.
- [ ] **Step 2:** `run_eval.py --list-remote-models groq`; choose one current general-purpose chat model; add it to `remote_models` as `groq/<id>`. Commit the config line (config only; frozen code untouched).
- [ ] **Step 3:** Run in order, each its own batch, stopping the hosted sequence if two in a row end aborted: `anthropic/claude-haiku-4-5` (`night-haiku45-3temps`, 54 runs), `anthropic/claude-haiku-5-5`, `anthropic/claude-sonnet-5-5`, `anthropic/claude-opus-5-5` (18 runs each), then Groq (`--temperatures 0.3`, 18 runs). A larger Groq batch only if the first had no invalid runs.
- [ ] **Step 4:** For each batch record in `session_summary.md`: batch id, freeze hash, run counts, the four cells per taxonomy, invalid count.

### Task 9: Gate 4

**Files:** Create `gates/gate4.py`. Test: `tests/test_gates.py`. Update `.claude/skills/run-gate/SKILL.md` only if its text no longer matches how Gate 4 runs.

- [ ] **Step 1:** Start the Gate 4 batch from the Run page in the browser: `qwen2.5:7b` and `llama3.1:latest`, all six scenarios, 0.1/0.3/0.7, 3 runs, batch id `gate4-<UTC stamp>` (108 runs). Watch the progress block update; note anything wrong with the live view and fix it in `dashboard/` only.
- [ ] **Step 2: Failing tests** for `gates/gate4.py` using a fixture batch: passes with a complete two-model batch containing a compromised run; fails with reason for (a) fewer than two models, (b) recorded runs ≠ planned runs, (c) a run without a stored result, (d) no compromised run.
- [ ] **Step 3:** Implement `gate4.py --batch-id <id>` on the `gates/_common.py` pattern: prints the plan, the four-cell matrix per model, temperature and taxonomy with invalid, parse-failure, unexecuted-attempt and distinct-trajectory counts, then for one compromised run (first by run order) what `dashboard.data.run_detail` returns: scenario, poison step index, the raw tool-call JSON of the tripping step, tripwires fired, canary ids, attempted calls. Prints the limitations. Writes `gates/evidence/gate4.txt` and `gate4.json`.
- [ ] **Step 4:** Run Gates 1 to 4 per the `run-gate` skill. Save a screenshot of the Inspect page on the same compromised run to `gates/evidence/gate4-inspector.png`.
- [ ] **Step 5:** Commit `feat(gate4): gate script and evidence`. **Stop: Gate 4 is a director gate.**

### Task 10: Wrap-up

- [ ] **Step 1:** Rewrite `session_summary.md`: current state, every batch run tonight with its cells, what is waiting on the director (Gate 4 sign-off, key replacement, two-call replies decision, merge), anything that failed or was skipped and why.
- [ ] **Step 2:** Final full suite, `check_rules.py`, `git status` clean apart from ignored files. Commit `docs: session summary after overnight run`.

## Self-review notes

- Spec coverage: regrade (Task 3, 4), `batch.json` (3), per-run results (2, 3), three pages (5 to 7), launcher (7), tests and rule (5 to 7), Gate 4 fresh batch from the Run page (9), overnight order and batches (4, 5, 8), memory rule (5), Groq and no Cerebras (8), CLAUDE.md change first (1), backlog entry for other providers (1).
- The spec's "console output going to `batch.log` in the batch folder" is changed to `results/_console/<batch_id>.log`, because `open_batch` refuses a folder that already exists and the log must be opened before `run_eval.py` creates it.
- The spec's order put the hosted batches before the dashboard was needed; here the Gate 4 batch (Task 9) runs after the hosted batches so the port is never contended.
