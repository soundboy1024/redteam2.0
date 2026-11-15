---
name: run-gate
description: Run a redteam2.0 verification gate (1 to 4), save its evidence, and report pass or fail. Use when asked to run, re-run or check a gate, or before claiming a phase is complete.
---

# Run a gate

Gates are scripts under `gates/`. Each one starts the decoy listener itself, exercises it, asserts, writes `gates/evidence/gateN.txt`, stops the listener it started, and exits 0 on pass or 1 on fail.

## Steps

1. Work from the repo root. Use the venv interpreter explicitly.
2. Run the rule checks first. Stop if either fails.

   ```
   .venv\Scripts\python.exe scripts\check_rules.py
   .venv\Scripts\python.exe -m traps.validate_scenarios
   ```

3. Run the gate and read the whole output, not just the last line.

   ```
   .venv\Scripts\python.exe gates\gateN.py
   ```

   Gate 4 is different: it starts no listener and calls no model. It reads the stored results of the Gate 4 batch (two models, all six scenarios, n_runs 3, started from the control panel's Run page) and needs its id:

   ```
   .venv\Scripts\python.exe gates\gate4.py --batch-id <gate4 batch id>
   ```

4. Report the last line (`GATE N: PASS` or `GATE N: FAIL <reason>`), the exit code, and the evidence rows the gate printed.
5. When running a later gate, re-run every earlier gate too. A later change must not break an earlier gate.

## Rules

- If the script says port 8999 is already in use, stop and tell the director. Never kill a process by name or sweep ports. Only the gate script stops the listener, and only the one it started.
- Gates 1 and 2 are self-certifying: a pass means continue. Gates 3 and 4 are director gates: show the evidence and wait for the director to confirm.
- A failing gate always stops work. Do not edit a gate script to make it pass; fix the code it tests.
- Re-running a gate rewrites its evidence file with new timestamps. Commit the evidence only when the gate script or the code under it changed.
