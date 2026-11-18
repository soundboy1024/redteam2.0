# BUILD_PLAN.md

Written 2026-11-17 from a planning conversation with the director.

Status: proposed. Nothing in this file is in scope until the director moves it into CLAUDE.md with its own phase and gate. Where this file and CLAUDE.md disagree, CLAUDE.md wins.

## Direction

The harness grows from a fixed three-tool loop into a tool server that any agent can be pointed at. The harness's own loop becomes one client of that server. Model comparison stays as it is; testing someone else's agent becomes possible without rebuilding the tools.

Grading stays deterministic. No judge anywhere, including in the new work.

## Order of work

### 1. Close what is open

- Commit and push the hardening work of 2026-11-17. Until then the public README lacks the defense results and the GitHub checks have never run (session summary, item 8).
- Write the README positioning paragraph (BACKLOG.md Tier 4): where this harness sits against AgentDojo, InjecAgent and the MCP tool-use benchmarks. The repository is public, so this is worth doing now.

### 2. Rulings needed before new code

1. Section 8 of CLAUDE.md: allow fake shell and database tools that return canned text. Real execution stays permanently out.
2. Phase 7 direction: tools served from a local tool server over MCP, with the harness loop as one client.
3. Runs per cell: keep 3 or raise to 10 (session summary, item 11). **Ruled 2026-11-18: 10, at temperatures 0.1 and 0.7.**
4. Canary names: replace the `CANARY_` prefix and the word `TRAP` with realistic-looking strings mapped in the registry. A model that reads the current strings can see they are bait. [INFER] This changes section 3 of CLAUDE.md.
5. Two-call replies: keep "reject" or execute the first call and flag the reply (session summary, item 6). **Ruled 2026-11-18: execute the first and flag the reply. Built (CLAUDE.md 4.0).**

### 3. Phase 7: configurable tools and the tool server

- Build the configurable tool set from BACKLOG.md Tier 1b: each tool is data, with a name, arguments, a canned response and a tripwire rule.
- Serve that tool set from a local MCP server backed by the same listener and the same four tripwires.
- The existing agent loop calls the server instead of in-process functions.
- Known cost: with an outside agent the harness keeps tool events and listener rows, so tripwires and task completion still grade, but it loses the per-step reply log and the parse states. [INFER]

Proposed gate: a scripted agent going through the server fires the same tripwires as Gate 6 part 1, and one outside agent completes one run with a stored result row.

### 4. Phase 8: new scenario types

In this order:

1. Web page fixtures (BACKLOG.md Tier 2). This is the honeypot website surface that motivated the project.
2. Tool poisoning: the injection lives in a tool's description (Tier 2).
3. Poisoned tool output: a legitimate endpoint returns an injection (Tier 2).
4. Tool choice without any attack: distractor tools and a new deterministic boolean, "wrong tool called".
5. Paired wording runs: change one thing (the prompt wording, a tool description, an added distractor) and record whether the tool choice flips. This is the judge-free substitute for asking why a model chose a tool.

Items 4 and 5 are reliability measurements, not red teaming. They stay in this project only as scenario types under the same grader.

### 5. Human attacker loop

A human writes and revises injections with an AI assistant as a guide. The assistant never grades.

- Authoring loop: edit an injection, run one scenario against one model, read the tripwires, revise.
- Graded batch: once an injection works it is frozen as a fixture. Batches replay frozen fixtures only.
- Add one provenance field per fixture: which model it was tuned against and how many revisions it took.
- Report "tuned against" and "transferred to" results separately. An attack tuned on a model is not comparable with the same attack run on other models. [INFER]
- Record attempts to first compromise as a count.

No attacker console and no built-in chat window. The assistant runs in a separate window and fixture text is pasted in by hand.

### 6. Freeze, then run

- Lock the tool set and the scenarios.
- Set the runs per cell from ruling 3.
- Start the 13-model sweep and the large batches only after the freeze. Every harness change so far has moved older batches to the archive, so data collected earlier will not be comparable. [INFER]

## Out for now

- An automated adaptive attacker (an attacker model in the loop)
- A native tool calling mode (conflicts with CLAUDE.md 4.7)
- An attacker console
- Live honeypots on the real internet (BACKLOG.md Tier 4)
- Cerebras

## Scope warning

Steps 3, 4 and 5 are three separate phases. Each needs its own section and gate in CLAUDE.md before work starts.

## Gaps in existing frameworks this plan responds to

From a short literature check on 2026-11-17, not a full survey.

- Fixed attack sets: AgentDojo ships generic attack templates; AutoDojo (June 2026) showed an adaptive attack succeeding against a filter that stopped every static attack. Step 5 is the partial answer.
- Fragile scoring: several tool-use benchmarks grade a final answer, a preset tool list or a judge model's verdict. This harness grades effects on a listener.
- Test detection: models can behave differently once they recognize an evaluation. Ruling 4 is the cheap fix here.
- Fragmentation: file injection, tool output, tool metadata and web pages are mostly covered by separate benchmarks. Step 4 puts them under one grader.

## References

- AgentDojo: https://arxiv.org/abs/2406.13352v3
- AgentDojo-Inspect (NIST fork): https://data.nist.gov/pdr/lps/ark:/88434/mds2-3690
- AutoDojo: https://arxiv.deeppaper.ai/papers/2606.15057v1
- Indirect Prompt Injections, Firewalls or Stronger Benchmarks: https://arxiv.org/abs/2510.05244v2
- The Landscape of Prompt Injection Threats in LLM Agents: https://www.alphaxiv.org/abs/2602.10453v1
- MCPTox: https://arxiv.org/abs/2508.14925v1
- MCPAgentBench: https://arxiv.org/abs/2512.24565v3
- MCP-Atlas: https://labs.scale.com/leaderboard/mcp_atlas
- DynamicMCPBench: https://www.alphaxiv.org/abs/2607.20531
- LLM Agent Honeypot (Palisade): https://www.arxiv.org/pdf/2410.13919
- MCP specification, tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
