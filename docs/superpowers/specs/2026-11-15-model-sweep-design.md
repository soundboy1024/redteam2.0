# Model sweep design

Status: draft for the director's approval. Nothing here is built. Date: 2026-11-15.

## Intent

Test many local models on this PC without keeping them all on disk: download one, check it runs, run the scenarios, confirm the results are stored, delete it, go to the next. Keep a record of every model tried, including the ones that do not fit or do not work, and why.

Why now: Gate 4 passed with two models. The results table needs more rows, and the PC can hold only one model in memory at a time.

## Goals

- One command runs a queue of models unattended and can be stopped and restarted without redoing finished models.
- Every model in the queue ends with a record, whatever happened to it.
- Results come from the same `run_eval.py` and the same grader as every other batch.
- The director's 13 installed models are never deleted.

## Not in this design

- Hosted models, a dashboard page for the sweep, running two models at once.
- Any change to `harness/`, `traps/`, `telemetry/` or the grader.

## What would make it a failure

- A model deleted before its results are confirmed on disk.
- A model that failed looking the same as a model that was never tried.
- A sweep that fills the disk or starves the PC of memory and has to be killed by hand.

## Approaches considered

1. **A separate script that drives `run_eval.py` (chosen by the director, 2026-11-15).** The harness and grader are untouched, each model gets its own batch folders, and a crash loses one model at most.
2. A sweep mode inside `run_eval.py`. Rejected: it changes the batch code Gate 4 certified, and one crash affects the whole sweep.
3. A sweep page in the dashboard. Deferred: it is a front end on approach 1.

## Design

### Files

- `sweep.py` (repo root, beside `run_eval.py`): the loop. It talks to Ollama over HTTP and starts `run_eval.py` as a separate process. It imports nothing from `harness/`, `traps/` or `telemetry/`.
- `sweep_queue.yaml`: the list of model tags, in order, with the memory and disk floors.
- `results/_sweep/<sweep_id>/sweep.json` and `sweep.md`: the fit record, as JSON and as a readable table, rewritten after every model.
- `results/_sweep/<sweep_id>/done/<model>.done`: one marker per model that finished cleanly.

### Steps for one model

1. **Skip** if its done marker exists.
2. **Preflight.** Port 8999 free, no batch alive, no model loaded in Ollama, free disk above the floor, free memory above the floor. If any check fails the sweep stops with the reason; it does not move on to the next model.
3. **Note whether the model is already installed.** A model that was present before the sweep is run and never deleted.
4. **Pull** with `ollama pull`. A failed pull (bad tag, network) is recorded and the sweep moves on.
5. **Load check.** One short request with the harness's `num_ctx` 8192. Record size in memory, share on the GPU, backend (Vulkan, ROCm or CPU, read from Ollama's log), tokens per second, and free memory after loading. If free memory after loading is under the floor, the model is recorded as "does not fit" and no batch is run.
6. **Run the batches.** Three batches per model, one per temperature (18 runs each, 54 in total), each through `run_eval.py --models <tag> --allow-any-model --batch-id sweep-<sweep_id>-<model>-t<temp>`. The model is unloaded between batches. The Results page already adds batches together.
7. **Memory watch.** While a batch runs, the sweep reads free memory every 30 seconds. Under the stop floor, it stops that batch through the pid in the batch's own `batch.json`, regrades it (so it shows as aborted) and records "stopped for memory at run N".
8. **Confirm results.** For each batch: exit code 0, `results.json` present, `batch.json` says not aborted, recorded runs equal planned runs.
9. **Unload, then delete** the model if the sweep pulled it. The record is written before the delete.
10. **Done marker** only if every step above succeeded. A model that failed gets a record with its reason and no marker, so the next start retries it unless the queue marks it skipped.

Why three batches per model: in the Gate 4 batch the Ollama runner for `llama3.1` grew from 6.2 GB to 13.95 GB over 54 runs and free memory fell to 3.1 GB. Unloading every 18 runs resets that. This is an assumption to check in the first sweep; the record holds runner memory at the start and end of each batch so it can be checked.

### Stopping the whole sweep

- Preflight failure (step 2).
- Three models in a row fail to pull or load: something is wrong with Ollama or the network, not with the models.
- Ctrl+C: the current batch is stopped the same way as in step 7 and the model is left without a marker.

### The fit record, per model

Tag, digest, download size, pulled by the sweep or already present, status (`completed`, `does_not_fit`, `pull_failed`, `load_failed`, `batch_failed`, `stopped_for_memory`), reason text, backend, GPU share, size in memory, tokens per second, free memory after load, lowest free memory during the batches, runner memory at the start and end of each batch, batch ids, run counts (valid, invalid), time taken, and whether it was deleted.

### Proposed queue (the director edits this)

Tags are checked by the pull itself; a tag that does not exist becomes a `pull_failed` record.

`llama3.2:1b`, `gemma3:4b`, `mistral:7b`, `granite3.3:8b`, `qwen3:8b`, `deepseek-r1:8b`, `hermes3:8b`, `dolphin3:8b`, `gemma3:12b`, `mistral-nemo:12b`, `phi4:14b`, `qwen2.5:14b`, `gpt-oss:20b`

The last three are near or over what fit in memory before; they are in the queue to produce "does not fit" records. About 15 minutes per model at the speed seen in Gate 4 for 7 to 8 billion parameter models, longer for the larger ones.

### Floors (proposed, in `sweep_queue.yaml`)

- Free disk before a pull: 30 GB.
- Free memory before a pull and after a load: 6 GB.
- Free memory stop floor during a batch: 2 GB.

## Rules carried over from CLAUDE.md

- No silent failures: every step logs what it did and every failure has a reason in the record.
- Processes are stopped only by the pid in a batch's own `batch.json`. Nothing is killed by name and no port is swept.
- The summary limitations (exact-match canaries, the two prompt-pointer scenarios) appear in `sweep.md`.

## Lines to add to CLAUDE.md if approved

- A section 4.9 "Model sweep" with the steps, the delete rule and the stop conditions above.
- `sweep.py` and `sweep_queue.yaml` in the directory layout.
- Phase 5 in the plan, with Gate 5: a sweep of two entries, one small real model (pulled, run, results confirmed, deleted) and one tag that does not exist (recorded as `pull_failed`), plus a restart that skips the finished model. Proposed as a director gate.

## Left to the builder

- How the backend is read from Ollama's log.
- Layout of `sweep.md`.
- Test structure: the loop takes its Ollama calls and process starts as arguments, so tests use fakes and download nothing.

## Calls made by Claude, not the director

- Three batches per model instead of one.
- A model the sweep pulled is deleted even when its batches failed (it can be pulled again; the record says why it failed).
- The three floors and the queue.
- Gate 5 as a director gate.
