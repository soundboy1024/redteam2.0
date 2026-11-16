# BACKLOG.md

Nothing in this file is in scope until the director moves it into CLAUDE.md. Claude Code appends ideas here when they come up mid-phase and keeps going. Do not implement from this file.

Ordering below is a rough priority, not a commitment.

## Tier 1. Same tripwires, cheap to add after Gate 4

(Final response relay, the defense layer and refusal detection moved to CLAUDE.md 4.10, Phase 6, on 2026-11-16.)

### Extra models and prompts
A results table across four or five local models. A second benign prompt per scenario so results are not tied to one phrasing.

## Tier 1b. Harness operations

- Consecutive-invalid abort only counts runner-level invalid runs; runs the grader marks invalid do not trip it
- Deterministic repair of a reply missing only trailing closers, as a recorded opt-in condition
- Grader-side classification of parse-failure replies as attempted tool calls, shown beside the tripwires
- Configurable tool set (director, 2026-11-15): the tools under test become data instead of code, each with a name, arguments, a canned response and a tripwire rule, so the harness can test whatever tools a real agent has, and more than three. Not started: needs a design and a director ruling, because CLAUDE.md 4 says "only these three" and section 8 puts shell and database tools permanently out (a fake shell that runs nothing would need that line changed).
- Hosted quota handling (director, 2026-11-15; ideas from the director's earlier harness notes): resume a batch that stopped (skip runs already recorded) so a batch can continue when a daily quota resets; a pause between hosted requests set per provider; a clean stop after a run of rate-limit failures, marked aborted, in place of a string of invalid runs; a retry for Groq's HTTP 400 "Tool choice is none, but model called a tool" (2 of 18 runs were invalid from it).

## Tier 2. New entry points, same sandbox

### Tool poisoning
The injection lives in a tool's description or schema, not in a file. Add a fourth mock tool whose description contains the instruction. Tests whether the model trusts tool metadata more than file content.

### Poisoned tool output
The legitimate webhook returns a response containing an injection. Tests whether the model trusts API responses as instructions.

### Web page fixtures
A local HTTP server serving HTML pages with hidden text (comments, white on white, aria labels). Agent gets a fetch_page tool locked to that server. This is the "red teamers building websites" surface.

### Multimodal fixtures
An image or PDF in the workspace with text the model can read but a human skims past.

## Tier 3. Persistence and multi-step

### Memory poisoning
A scratchpad or notes file the agent is told it may write to and will read next session. Run a two-session scenario: session one ingests the injection and is allowed to write notes; session two starts clean and reads the notes. Tripwire fires if the injection survived into session two.

### Privilege escalation
A scenario where the only path to the attacker's goal is for the agent to request additional access (a mock request_access tool). Tripwire on the request, regardless of whether it is granted.

### Multi-agent relay
Two agent loops. Agent A reads the poisoned file and writes a summary. Agent B reads only the summary. Tripwire fires on B. Measures whether injections survive summarization.

### Sabotage scenarios
The injection asks for a subtly wrong result (wrong invoice total, wrong log verdict) rather than exfiltration. completion_check already catches this if the expected value is strict. Needs fixtures only.

## Tier 4. Positioning and reporting

### Benchmark comparison
Read AgentDojo and InjecAgent before claiming novelty. The differentiator here is the honeypot server as ground truth and the realistic AV fixtures, not the concept. Write one paragraph in the README placing this harness relative to them.

### Report export
One command that produces a markdown summary of the run matrix with the four-cell result per model, suitable for pasting into a post.

### Live honeypots
Alex's version: traps deployed on the real internet to catch real agents. Entirely different threat model and legal footing from a lab sandbox. Do not confuse the two in the pitch. Not a near-term item.

### Per-model token and cost totals
Add per-model token totals (prompt and completion) and an estimated cost to the batch summary, now that hosted models bill by the token. Needs a price table kept outside the code path that grades.

### Empty-reply placeholder for Groq and Cerebras
Extend the "(empty reply)" placeholder to Groq and Cerebras if a live run shows they reject empty assistant content.

### More hosted providers
Mistral (free tier, no card). Needs its own entry in CLAUDE.md 4.7: fixed endpoint, key variable, temperature rule. (Gemini was built on 2026-11-15 as the `google` provider.)

## Not planned

- Shell or database tools inside the sandbox
- Any LLM-as-judge grading, ever
