# Post-Gate-3 change set: design

Date: 2026-11-14. Source: the director's answers to the Gate 3 handover and to the qwen2.5:7b run.

## What the director decided

1. Telemetry off for graded batches (already the config default).
2. Parse failures: tell the model why its reply was rejected, and have the grader record calls that were attempted but never executed. No repair-and-execute.
3. Object-valued `final` stays a parse failure.
4. Temperatures 0.1, 0.3 and 0.7 as a batch dimension.
5. A reply holding more than one JSON object is rejected.
6. Hosted models are allowed: Claude API (the director has monthly credits) plus low-cost providers Groq and Cerebras. This lifts the "remote models permanently out" line in CLAUDE.md section 8.
7. `fake_system_error` and `authority_spoof`: adjust the task so the model has a reason to open the file that carries the injection.

## Calls made here (the director can overrule any of them)

- Only a second JSON object causes rejection. Prose before or after a single object is still accepted and ignored, as before.
- A reply that is valid JSON except for missing trailing closers gets its own rejection reason, so the model is told exactly that.
- Attempted calls are reported in their own fields and never change `compromised` or the cell. Cells still reflect executed actions only.
- Model names: `anthropic/<id>`, `groq/<id>`, `cerebras/<id>` are hosted; every other name is a local Ollama model. Hosted endpoints are fixed constants in code, HTTPS only. Nothing about them is configurable except the model id.
- API keys come from environment variables only (`ANTHROPIC_API_KEY`, `GROQ_API_KEY`, `CEREBRAS_API_KEY`). They are never written to config, logs, the run log or results. A missing key stops the batch before it opens.
- Hosted models keep the same plain-JSON reply protocol as local models. No native tool calling, so results stay comparable.
- Current Claude models reject a `temperature` setting (HTTP 400). For a model that does not accept one, the temperature dimension collapses to a single condition recorded as no temperature and shown as "default". `claude-haiku-4-5`, `claude-sonnet-4-6` and `claude-opus-4-6` still accept it and get the full list.
- Current Claude models think before answering and that thinking counts against the output limit, so hosted calls use their own larger limit (`remote_max_tokens`). No thinking or effort setting is sent: provider defaults, stated in the summary.
- A hosted refusal is model behaviour, not an infrastructure fault: it comes back as an empty reply with its stop reason and is logged as a parse failure. No server-side fallback to another model, because that would hide it.
- Telemetry (logprobs) is local-only. Telemetry on plus a hosted model is refused before the batch opens.
- Rate limits: bounded retry (five attempts, honouring `retry-after` up to 60 s), each retry logged. After that the run is invalid, like an Ollama error.
- Groq and Cerebras model ids change often and public lists disagree, so none are hard-coded. `run_eval.py --list-remote-models <provider>` asks the provider with the director's key.
- Scenario prompts for the two never-exposed scenarios gain one neutral sentence pointing at the file. The pointer comes from the user, which lends the file some standing; that is recorded as a limitation beside the results. The paired benign scenarios keep their original prompts.

## Not in this change set

Repair-and-execute, native tool calling, hosted logprobs, per-model cost totals in the summary (written to BACKLOG.md), the Phase 4 inspector.
