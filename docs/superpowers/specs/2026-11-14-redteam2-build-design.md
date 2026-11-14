# redteam2.0 build design (addendum to CLAUDE.md)

Date: 2026-11-14

CLAUDE.md is the specification. This note records only how the build is run and the calls made where the spec is silent.

## Intent

Build Phases 1 to 4 of CLAUDE.md this weekend with as little director keyboard time as possible, without weakening the deterministic gates. The thirty second demo in section 7 is the target.

## Goals, non-goals, anti-goals

- Goal: Gates 1 and 2 pass unattended, with saved evidence. Gates 3 and 4 are reviewed by the director.
- Non-goal: anything in BACKLOG.md.
- Anti-goal: a gate that "passes" because Claude said so. Every gate is a script whose output is saved and re-runnable.

## Approaches considered

1. Hybrid gates (chosen by the director). Claude runs Gates 1 and 2 and continues; stops at Gates 3 and 4.
2. Fully autonomous. Fastest, but the telemetry decision at Gate 3 would be made by Claude.
3. As originally written. Stop at every component; needs the director present all day.

## How the build runs

- Setup: git init, venv at .venv, pinned requirements.txt, project permission allowlist for python, pytest, curl and git inside this folder.
- One fresh subagent per plan task, test first, review after each task.
- Gate scripts: gates/gate1.py to gates/gate4.py, evidence saved to gates/evidence/.
- Two hooks enforce operating rules 3 and 4 mechanically:
  - fail if any file under harness/ imports from traps/ or telemetry/
  - fail on bare except, or except Exception followed by pass
- Project skills, built after Phase 1 exists: run-gate, new-scenario.

## Claude's calls (not specified in CLAUDE.md, director may overrule)

- Agent loop step cap: 12 steps. Hitting the cap ends the run as task_completed false, logged, never silent.
- Tools accept relative paths inside the workspace (logs/dante_sync.log, config/credentials.json). Anything resolving outside the workspace is rejected and logged.
- Project folder stays redteam2.0; the redteam2/ name in section 5 is treated as the same folder.
- Models for the Gate 4 matrix: llama3.2:3b and qwen2.5:7b (integrated graphics; 14b models reserved for single showcase runs).
- Streamlit inspector on port 8503 with a venv-explicit .bat launcher and port-specific kill.
- Listener is started and stopped by the gate scripts and tests, killed by port 8999 only.
- Since harness/ may not import traps/, the tools receive scenario data (canary_files, allowed_endpoints) as plain arguments from the runner. The runner reads traps/scenarios.json as a data file; it does not import any Python from traps/.

## Left to the builder

Module internals, test layout beyond the two files named in section 5, and fixture wording, within the rules of CLAUDE.md section 2.
