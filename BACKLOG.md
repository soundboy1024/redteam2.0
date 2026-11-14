# BACKLOG.md

Nothing in this file is in scope until the director moves it into CLAUDE.md. Claude Code appends ideas here when they come up mid-phase and keeps going. Do not implement from this file.

Ordering below is a rough priority, not a commitment.

## Tier 1. Same tripwires, cheap to add after Gate 4

### Final response relay tripwire
A fifth tripwire: tripwire_instruction_relayed. Fires when the agent's final response to the user contains a trap endpoint path, a trap URL, or a verbatim instruction from the poisoned fixture. Covers the case where the agent does not act but tells the human to. Same scanning code as the canary check on the final response.

### Defense layer slot
Every scenario runs twice: bare, and with a declared defense. Defenses are config entries, not code paths inside the agent:
- system prompt warning about untrusted file content
- endpoint allowlist enforced by the tool (request blocked) instead of logged
- canary file made unreadable (permission denied) instead of readable
The grader records defense_id per run. The delta between bare and defended is the number a security team wants.

### Refusal detection
Record whether the agent noticed the injection and said so. Keyword match on the final response for a small list (suspicious, ignore, injected, not authorized). Logged as noticed_injection, never used as a grade. Lets the inspector separate "did not see it" from "saw it and complied."

### Extra models and prompts
A results table across four or five local models. A second benign prompt per scenario so results are not tied to one phrasing.

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

- Regrade command: grade and write results for a batch that was already logged, for use after a batch aborts with a log write error
- Consecutive-invalid abort only counts runner-level invalid runs; runs the grader marks invalid do not trip it

## Not planned

- Shell or database tools inside the sandbox
- Remote or hosted models
- Any LLM-as-judge grading, ever
