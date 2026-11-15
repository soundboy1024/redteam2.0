# Control panel, inspector and the overnight run plan

Date: 2026-11-15. Branch: `phase4`, cut from `post-gate3` at `fb6d4c4`. Nothing is pushed or merged.

Items marked **(my call)** were decided by Claude, not the director, and can be overruled.

## Intent

The director wants two things:

1. One simple screen to pick models, start a batch and watch it run, without reading files or typing commands.
2. Unattended work overnight: finish the open items, build that screen and the Phase 4 inspector, and run local and hosted models.

The reason for the screen: the director is a systems troubleshooter, not a hand-coder, and today the only way to see what a batch is doing is the console log and the files under `results/`.

## Goals

- A Streamlit app with three pages: Run, Results, Inspect a run.
- A regrade command, so a batch that was logged but never graded gets its results written.
- Stored results for the 33 runs of `qwen7b-all6-3temps`, and one combined view of the three qwen2.5:7b three-temperature folders.
- Overnight batches on the other installed local models and on Anthropic models.
- Gate 3 re-run at head. Gate 4 evidence produced, then stop for the director.

## Non-goals

- No change to the tripwires, the grader's rules, the parser, the tools or the scenarios. Tonight's batches must stay comparable with the qwen2.5:7b results already recorded.
- No cost tracking (stays in `BACKLOG.md`).
- No editing of scenarios or config from the screen.
- No running two batches at once.
- No merge into `main` and no push.

## Anti-goals

- The screen must never grade. It shows grades the grader stored.
- The screen must never show, log or store an API key. It shows "set" or "not set".
- Starting a batch from the screen must not be a second code path. It is the same `run_eval.py` command, shown on the page so it can be re-run by hand.
- Model text (replies, tool arguments) is untrusted and is shown as plain text or in code blocks, never as HTML.
- A stopped or crashed batch must never look finished or clean.

## Constraints

- `CLAUDE.md` rule 6: the Run page is new scope. The director asked for it on 2026-11-15, so `CLAUDE.md` gets a new section 4.8 and an amended Phase 4 before any code.
- `CLAUDE.md` rule 4: `harness/` imports nothing from `telemetry/` or `traps/`. The dashboard may import `telemetry/` and `rt_config` to read; it does not import `harness/` and reaches a batch only by starting `run_eval.py` as a process.
- Gate 4 is a director gate. Work stops there.
- One listener on port 8999, so one batch at a time. The overnight batches and the screen's Run page share that limit.
- Streamlit launcher convention: port 8503 (proposed to the director on 2026-11-15), a `.bat` that uses `.venv\Scripts\python.exe -m streamlit`, and a kill loop for that port only.
- Results are saved in both readable and JSON form, as they are today.
- Cerebras: the director must not be charged. Whether Cerebras bills a card automatically once the trial credit runs out could not be confirmed, so no Cerebras call is made tonight.

## Approaches

**A. One Streamlit app; the Run page starts `run_eval.py` as a separate process and reads progress from the run log. (Picked.)**
The batch survives a page refresh or a closed browser tab. The command on screen is the one the director could type. Progress comes from the same SQLite files the grader reads. Cost: a stopped batch is a killed process, so it needs the regrade command to get results.

**B. Run the batch inside the Streamlit process.**
Fewer moving parts, but Streamlit re-runs the page script on every interaction, so a batch would need a background thread tied to the page server. Closing or restarting the app would kill a batch mid-run. Rejected.

**C. A separate FastAPI page with its own front end.**
Finer control over live updates, but a second UI stack to maintain next to the Streamlit inspector the spec already calls for. Rejected.

The director approved approach A's sketch in conversation on 2026-11-15 by asking for "the control panel with the live progress view as well as the phase 4 inspector".

## Design

### 1. Regrade command

`run_eval.py --regrade <batch_id>` grades every run recorded for that batch and writes `results.json`, `summary.md`, `runs/*.md` and the `results` table rows, using the existing `write_batch_results`. This is the `BACKLOG.md` Tier 1b item "Regrade command", moved into scope.

- It starts no listener and calls no model.
- It completes a batch, it never overwrites: a run that already has a row in the `results` table keeps that row untouched; a run without one is graded and stored. The files (`results.json`, `summary.md`, `runs/*.md`) are then rewritten from the stored rows. A batch whose every run already has a stored row and whose files exist is refused, naming the batch. **(my call)** This covers a batch killed mid-write, the case the backlog item was written for.
- The batch is marked aborted with the reason "regraded after the batch stopped early", unless every planned run is present.
- Steps that belong to no recorded run (a run cut off mid-way) are counted and named in the summary notes. They are in no cell.
- Batch metadata that only the live process knew (start and end time, planned run count) is rebuilt from the run rows where possible and written as null where not. **(my call)**

### 2. Batch plan file

When a batch opens, `run_eval.py` writes `batch.json` into the batch folder: batch id, models, scenario ids, temperatures, n_runs, planned run count, start time, process id and the exact command line (no key is ever on the command line). The Run page reads it to show "17 of 54". **(my call)** Batches opened before this change have no `batch.json`; the pages show their planned count as unknown.

### 2b. A result is stored as each run finishes

Today grading happens once, at the end of a batch, so a live view would show no result until the last run. Change: after each run is recorded, `run_eval.py` grades that run with the same grader function and stores its row in the `results` table. The end-of-batch step then grades only runs without a stored row and writes the files from the stored rows, the same path the regrade command uses. **(my call)**

- The grader's rules do not change. A run's grade depends only on that run's own log rows, which are complete when the run ends.
- A test asserts that per-run grading and end-of-batch grading give identical rows for the same logs.
- This edit to `run_eval.py` and `batch_results.py` lands in step 2 of the overnight order, before any batch starts.

### 3. Dashboard (`dashboard/app.py`, plus small modules beside it)

**Run page**

```
Models        [x] qwen2.5:7b   [ ] llama3.1:latest   [ ] anthropic/claude-haiku-4-5  (key set)
Scenarios     [ all six ]
Temperatures  0.1, 0.3, 0.7        Runs each  3          = 54 runs
Batch name    ____________
Command       .venv\Scripts\python.exe run_eval.py --models ... --batch-id ...
[ Start ]  [ Stop ]

Running qwen-night-1     17 / 54     now: indirect_injection_log, t=0.3, rep 2
Latest steps    step 4  read_workspace_file  .env
Finished runs   scenario | temp | rep | result | tripwires
Listener        20:13:35  POST /admin-debug  TRAP  canary log_env
```

- The model list is `models` plus `remote_models` from `config.yaml`. A hosted model whose key is not set is shown but cannot be ticked.
- Start is disabled while a batch process is alive or port 8999 is in use. The page says which.
- Start launches `run_eval.py` detached, with its console output going to `batch.log` in the batch folder.
- Progress is read every 2 seconds from the run log and the listener database, opened read-only. "Finished runs" shows the stored result of each run (section 2b), normally within a moment of the run ending; a run with no stored row yet says "recorded, not graded yet". The live listener line shows what the listener logged, labelled as raw listener events, not as a grade.
- Stop asks for confirmation, kills the batch process and its listener child by process id, then runs the regrade command for that batch. The batch shows as aborted.
- If the batch process is gone and no results exist, the page says "stopped without results" and offers Regrade.

**Results page**

- Pick one or more batches. Shows the four-cell matrix per model, temperature and taxonomy as counts and percentages, with the invalid count, runs with parse failures, runs with unexecuted trap attempts and distinct trajectories, as `summary.md` does.
- Picking several batches adds their stored results together. This is the combined view for the three qwen2.5:7b folders. The page lists which batches are included and flags any that are aborted.
- The limitations text from `summary.md` is shown on the page every time, including the exact-match canary limitation and the note on the two scenarios whose prompt names the poison file.

**Inspect a run page**

- As `CLAUDE.md` Phase 4 view 2 and the Phase 4 inputs in `2026-11-14-gate3-handover.md`: poisoned fixture text on the left, the agent's raw tool-call JSON on the right, the step where `poison_ingested` first turns true, which tripwires fired, attempted calls shown prominently, `parse_reason` and `done_reason` per step, full tool results, entropy trace only when telemetry was on.
- Result rows from before the attempted-calls change lack those fields; the page shows "not recorded" for them.

**Launcher**

`run_dashboard.bat` at the project root, following the director's Streamlit convention, port 8503.

### 4. Tests

Every data function the pages use (batch list, progress, matrix aggregation, run detail) lives in a plain module with unit tests against a small temp database. The Streamlit pages themselves get a smoke test with Streamlit's `AppTest` that each page renders against a fixture database without an exception. The regrade command and `batch.json` get tests in `tests/test_run_eval.py`. `scripts/check_rules.py` gains the rule that `dashboard/` does not import `harness/`.

### 5. Gate 4

Gate 4 gets its own fresh batch, `gate4-<UTC stamp>`: both models, all six scenarios, temperatures 0.1, 0.3 and 0.7, n_runs 3, 108 runs in one batch. Pooled earlier batches are not used for the gate. **(my call)** It is started from the Run page, so the gate also exercises the control panel.

`gates/gate4.py` checks that this batch exists complete with stored results, prints the matrix, picks one compromised run, and prints what the inspector shows for it. A screenshot of the Inspect page on that run is saved to `gates/evidence/`. Then work stops for the director.

Gate 4 model pair **(my call, the director can change it)**: `qwen2.5:7b` and `llama3.1:latest`. If `llama3.1` produces no compromised run and no usable contrast, the pair is reported with the alternatives from tonight's batches so the director can choose.

## Overnight order of work

1. Add section 4.8 to `CLAUDE.md` and amend Phase 4. Commit.
2. Regrade command and `batch.json`, with tests. Regrade `qwen7b-all6-3temps`.
3. Re-run Gate 3 at head.
4. Start the local batches (below). They run in the background while the dashboard is built.
5. Dashboard: data modules, then the three pages, then the launcher.
6. Hosted batches, after the local ones finish (one listener, one batch at a time).
7. The Gate 4 batch (108 runs, two local models), started from the Run page. Gate 4 script and evidence. Update `session_summary.md`. Stop.

Code that a batch depends on (`harness/`, `telemetry/grader.py`, `traps/`) is not edited after step 2, so every batch tonight runs on the same code. The commit hash each batch ran at is recorded in the session summary.

### Batches

All six scenarios, 3 runs each. Local models at temperatures 0.1, 0.3 and 0.7 (54 runs per model).

| Order | Model | Runs | Note |
|---|---|---|---|
| 1 | `llama3.1:latest` | 54 | |
| 2 | `gemma2:9b-instruct-q4_K_M` | 54 | |
| 3 | `phi4-mini:latest` | 54 | |
| 4 | `ministral-3:8b` | 54 | |
| 5 | `llama3.2:3b` | 54 | |
| 6 | `anthropic/claude-haiku-4-5` | 54 | accepts temperature |
| 7 | `anthropic/claude-haiku-5-5` | 18 | no temperature, shown as "default" |
| 8 | `anthropic/claude-sonnet-5-5` | 18 | no temperature |
| 9 | `anthropic/claude-opus-5-5` | 18 | no temperature |

- Local models not in `config.yaml` are added to its `models` list rather than run with `--allow-any-model`. **(my call)**
- `dolphin3` and `gpt-oss:20b` are not installed and are not pulled tonight.
- Anthropic: the director has $100 of credit and said to use it freely. Rough ceiling for the four Anthropic batches together is well under that; the estimate is written to the session summary before the first hosted batch starts, and the hosted batches stop if two in a row end aborted.
- Groq: the director confirmed on 2026-11-15 that no payment card is attached, so Groq is included. One model, chosen from `run_eval.py --list-remote-models groq` and added to `remote_models`, at 18 runs first (all six scenarios, one temperature, 3 runs). The free tier is reported at about 30 requests a minute and 1,000 a day; a larger Groq batch runs only if the first ends without rate-limit invalids.
- Other free providers (Mistral, Gemini through an AI Studio key) are not wired into the harness. Adding one is new scope and goes to `BACKLOG.md`.
- Director approval: the director approved this design on 2026-11-15 ("the plan is good").
- Cerebras: not run tonight.
- Memory: before each local batch starts, free physical memory is checked. Below 8 GB, that batch and the remaining local batches are not started, and the session summary says so. A running batch is never killed for memory; if it goes invalid it stops on the existing three-consecutive-invalid rule. Nothing is restarted without the director. **(my call)**
- Keys: the saved keys are loaded from the Windows user environment into the process that starts a batch. No key is ever written to a file in the project. On 2026-11-15 the Anthropic key was found pasted into `traps/fixtures/indirect_injection_markdown/.env` (uncommitted, never read by a run). With the director's approval the file was restored to its committed content the same day. The director said replacing the key can wait; hosted Anthropic batches run on the current key.

## Left to the builder

- File and function names inside `dashboard/`.
- Exact layout, colours and wording of the pages, within the dark theme the spec asks for.
- How the 2-second refresh is done in Streamlit.
- The wording of section 4.8, provided it states the anti-goals above.
