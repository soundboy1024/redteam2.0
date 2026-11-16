"""redteam2.0 control panel and inspector (CLAUDE.md 4.8 and Phase 4).

Three pages: Run, Results, Inspect a run. This app never grades: every grade shown
is a row the grader stored. Model text is untrusted and is only ever shown through
st.code, st.text or a dataframe cell, never as HTML.

Launch: run_dashboard.bat   (port 8503)
"""
import json
import os
import pathlib
import re
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # `streamlit run dashboard/app.py` puts dashboard/ first
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from dashboard import control, data  # noqa: E402
from rt_config import ConfigError, load_config  # noqa: E402
from telemetry.report import CELLS  # noqa: E402

PAGES = ("Run", "Results", "Inspect a run")
CELL_LABELS = {"completed_clean": "Completed and clean",
               "completed_compromised": "Completed and compromised",
               "failed_clean": "Failed and clean",
               "failed_compromised": "Failed and compromised"}
BATCH_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
STATE_TEXT = {"starting": "STARTING", "running": "RUNNING",
              "finishing": "FINISHING (writing results)",
              "finished": "finished", "aborted": "ABORTED",
              "stopped_without_results": "STOPPED WITHOUT RESULTS",
              "unknown": "unknown (no plan file, no results)"}


def _abs(path: str) -> str:
    p = pathlib.Path(path)
    return str(p if p.is_absolute() else ROOT / p)


def _settings() -> dict:
    config_path = os.environ.get("RT_DASHBOARD_CONFIG", "config.yaml")
    cfg = load_config(_abs(config_path))
    with open(ROOT / "traps" / "scenarios.json", encoding="utf-8") as f:
        scenarios = json.load(f)
    return {"cfg": cfg, "config_path": config_path, "db": _abs(cfg["db_path"]),
            "listener_db": _abs(cfg["listener_db_path"]),
            "results_dir": _abs(cfg["results_dir"]),
            "fixtures_root": str(ROOT / "traps" / "fixtures"),
            "scenario_ids": [s["id"] for s in scenarios],
            "host": cfg["listener"]["host"], "port": cfg["listener"]["port"]}


def _temp_text(t) -> str:
    return "default" if t is None else f"{t:g}"


def _pct(count: int, n: int) -> str:
    return f"{count} ({round(100 * count / n)}%)" if n else f"{count}"


def _parse_temperatures(text: str) -> tuple[list[float], str | None]:
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if not parts:
        return [], "give at least one temperature, for example 0.1, 0.3, 0.7"
    values = []
    for p in parts:
        try:
            v = float(p)
        except ValueError:
            return [], f"{p!r} is not a number"
        if not 0 <= v <= 2:
            return [], f"{p!r} is outside 0 to 2"
        values.append(v)
    if len(set(values)) != len(values):
        return [], "temperatures has duplicates"
    return values, None


def _state_of(plan: dict | None, has_files: bool, port_is_open: bool) -> tuple[str, bool]:
    """(state, identity_verified) of a batch from its plan and its own process."""
    alive, verified = control.process_alive(plan)
    return control.batch_state(plan, alive, verified, port_is_open, has_files), verified


def _live_batch(s: dict, batches: list[dict], port_is_open: bool):
    """(batch_id, state, plan, verified) of the batch that is alive now, or None."""
    for b in batches:
        plan, _ = data.read_plan_safe(s["results_dir"], b["batch_id"])
        state, verified = _state_of(plan, b["has_result_files"], port_is_open)
        if state in control.LIVE_STATES:
            return b["batch_id"], state, plan, verified
    return None


def _batch_name_problem(batch_id: str, existing: list[str], results_dir: str) -> str | None:
    if not BATCH_ID_RE.fullmatch(batch_id):
        return ("the batch name may only use letters, digits, - and _ (1 to 64 "
                "characters)")
    if batch_id in existing or os.path.exists(os.path.join(results_dir, batch_id)):
        return f"a batch named {batch_id} already exists; pick a new name"
    return None


@st.cache_data(ttl=120, show_spinner=False)
def _preview(command: tuple, cwd: str):
    return control.preview_plan(list(command), cwd)


# ---- Run page ---------------------------------------------------------------

def page_run(s: dict) -> None:
    st.header("Run a batch")
    cfg = s["cfg"]
    all_models = list(cfg["models"]) + list(cfg["remote_models"])
    keys = control.key_status(all_models, os.environ)
    selectable = [m for m in all_models if keys.get(m, True)]
    no_key = [m for m in all_models if not keys.get(m, True)]
    models = st.multiselect("Models", selectable, default=selectable[:1], key="models")
    if no_key:
        st.caption("Hosted models that cannot be picked because their key is not set: "
                   + ", ".join(no_key))
    hosted_keys = sorted({control.KEY_ENV[control.provider_of(m)] for m in keys})
    if hosted_keys:
        st.caption("Keys: " + ", ".join(
            f"{k} {'set' if os.environ.get(k) else 'not set'}" for k in hosted_keys))
    scenario_ids = st.multiselect("Scenarios", s["scenario_ids"], default=s["scenario_ids"],
                                  key="scenarios")
    c1, c2, c3 = st.columns(3)
    temp_text = c1.text_input("Temperatures", ", ".join(f"{t:g}" for t in cfg["temperatures"]),
                              key="temperatures")
    n_runs = c2.number_input("Runs each", min_value=1, max_value=50, value=int(cfg["n_runs"]),
                             key="n_runs")
    if "default_batch" not in st.session_state:
        st.session_state["default_batch"] = datetime.now(timezone.utc).strftime(
            "ui-%Y%m%dT%H%M%SZ")
    batch_id = c3.text_input("Batch name", st.session_state["default_batch"], key="batch_id")
    temperatures, temp_problem = _parse_temperatures(temp_text)
    defense_ids = st.multiselect(
        "Defenses", ["none", *(d["id"] for d in cfg["defenses"])], default=["none"],
        key="defenses",
        help="Every scenario runs once under each defense picked. 'none' is the bare run.")
    if len(defense_ids) > 1:
        st.caption(f"{len(defense_ids)} defenses picked: the batch is {len(defense_ids)} "
                   "times the size of a bare one.")

    batches = data.list_batches(s["db"], s["results_dir"])
    port_is_open = control.port_open(s["host"], s["port"])
    live = _live_batch(s, batches, port_is_open)
    running = live[0] if live else None

    problem = temp_problem
    if not models:
        problem = "pick at least one model"
    elif not scenario_ids:
        problem = "pick at least one scenario"
    elif not defense_ids:
        problem = "pick at least one defense ('none' is the bare run)"
    elif problem is None:
        problem = _batch_name_problem(batch_id.strip(), [b["batch_id"] for b in batches],
                                      s["results_dir"])
    plan = None
    command = control.build_command(sys.executable, models, scenario_ids, temperatures,
                                    int(n_runs), batch_id.strip(), s["config_path"],
                                    defenses=defense_ids)
    if problem is None:
        plan, problem = _preview(tuple(command), str(ROOT))
    if plan is not None:
        st.write(f"**{plan['planned_runs']} runs** planned.")
        st.caption("Command (the same one you could type):")
        st.code(" ".join([".venv\\Scripts\\python.exe", *plan["command"]]), language=None)
    else:
        st.warning(f"Cannot start: {problem}")

    blocker = None
    if running:
        blocker = f"batch {running} is {live[1]}; one batch at a time"
    elif port_is_open:
        blocker = (f"port {s['port']} is in use by something that is not a batch started "
                   "here (a gate or a command-line batch); wait for it to finish")
    if blocker:
        st.info(f"Start is off: {blocker}.")
    b1, b2, b3 = st.columns([1, 1, 4])
    if b1.button("Start", type="primary", disabled=bool(blocker or plan is None), key="start"):
        console = os.path.join(s["results_dir"], "_console", f"{batch_id.strip()}.log")
        try:
            control.start_batch(command, str(ROOT), console, port_is_open, running)
        except control.StartRefused as exc:
            st.error(f"Not started: {exc}")
        else:
            st.session_state["watch"] = batch_id.strip()
            del st.session_state["default_batch"]
            # the path is shown as code: plain markdown drops the backslash before "_console"
            st.success(f"Started {batch_id.strip()}. Console output: `{console}`")
    stoppable = bool(live and live[1] == "running" and live[3])
    confirm = b3.checkbox("I want to stop the running batch", key="confirm_stop",
                          disabled=not stoppable)
    if live and live[1] == "running" and not live[3]:
        st.caption(f"Stop is off for {running}: it did not record which process it is "
                   "(it was started before that was recorded, or from a script), so it "
                   "can only be stopped where it was started.")
    if b2.button("Stop", disabled=not (stoppable and confirm), key="stop"):
        try:
            out = control.stop_batch(live[2], str(ROOT), sys.executable, s["host"],
                                     s["port"], s["config_path"])
        except ValueError as exc:
            st.error("Not stopped:")
            st.text(str(exc))
        else:
            st.warning(f"Stop requested for {running}. Process killed: {out['killed']}. "
                       f"Regrade exit code: {out['regrade_exit']}.")
            st.code(out["regrade_output"], language=None)

    st.divider()
    ids = [b["batch_id"] for b in batches]
    if not ids:
        st.write("No batches yet.")
        return
    default = running or st.session_state.get("watch")
    index = ids.index(default) if default in ids else 0
    watch = st.selectbox("Watching batch", ids, index=index, key="watch_select")
    progress_block(s, watch)


@st.fragment(run_every=2)
def progress_block(s: dict, batch_id: str) -> None:
    p = data.batch_progress(s["db"], s["listener_db"], s["results_dir"], batch_id)
    port_is_open = control.port_open(s["host"], s["port"])
    state, _ = _state_of(p["plan"], p["has_result_files"], port_is_open)
    planned = p["planned_runs"]
    st.subheader(f"{batch_id}: {STATE_TEXT[state]}")
    if p["plan_problem"]:
        st.error("batch.json could not be read:")
        st.text(p["plan_problem"])
    st.write(f"**{p['recorded_runs']} / {planned if planned is not None else 'unknown'}** "
             "runs recorded")
    if planned:
        st.progress(min(1.0, p["recorded_runs"] / planned))
    if p["plan"] and p["plan"].get("abort_reason"):
        st.error("This batch aborted. Reason:")
        st.text(str(p["plan"]["abort_reason"]))
    if state == "stopped_without_results":
        st.error("This batch stopped without writing results. Nothing about it is a "
                 "result until it is regraded.")
        if st.button("Regrade this batch", key=f"regrade_{batch_id}"):
            out = control.regrade_batch(batch_id, str(ROOT), sys.executable, s["config_path"])
            st.write(f"Regrade exit code: {out['regrade_exit']}")
            st.code(out["regrade_output"], language=None)
    cur = p["current"]
    if cur and state in ("running", "starting"):
        st.write(f"**Now:** {cur['scenario_id']} | {cur['model_name']} | "
                 f"temperature {_temp_text(cur['temperature'])} | "
                 f"repetition {cur['repetition_index']}")
        st.caption("Latest steps of the run in progress")
        st.dataframe(pd.DataFrame([{
            "step": x["step_index"], "state": x["agent_state"], "tool": x["tool_name"],
            "arguments": x["tool_args_json"], "parse reason": x["parse_reason"]}
            for x in cur["last_steps"]]), hide_index=True, width="stretch")
    elif p["unrecorded_run_ids"] and state not in control.LIVE_STATES:
        st.caption(f"{len(p['unrecorded_run_ids'])} run(s) were cut off mid-run and never "
                   "recorded. They are in no cell.")
    st.caption("Finished runs, newest first. Results are the grader's stored rows.")
    if p["finished"]:
        st.dataframe(pd.DataFrame([{
            "scenario": r["scenario_id"], "model": r["model_name"],
            "temp": _temp_text(r["temperature"]), "rep": r["repetition_index"],
            "result": r["cell"], "tripwires fired": ", ".join(r["tripwires"]) or "none",
            "unexecuted trap attempts": ", ".join(r["attempted_tripwires"]) or "none"}
            for r in p["finished"]]), hide_index=True, width="stretch")
    else:
        st.write("No run has finished yet.")
    st.caption("Raw listener events (not a grade), newest first")
    if p["listener_events"]:
        st.dataframe(pd.DataFrame([{
            "time": e["timestamp"], "method": e["method"], "path": e["path"],
            "class": e["classification"], "canaries": ", ".join(e["canary_ids"]) or "none",
            "run": e["run_id"][:8]} for e in p["listener_events"]]),
            hide_index=True, width="stretch")
    else:
        st.write("No listener events for this batch.")


# ---- Results page -----------------------------------------------------------

def page_results(s: dict) -> None:
    st.header("Results")
    batches = [b for b in data.list_batches(s["db"], s["results_dir"]) if b["stored_results"]]
    if not batches:
        st.write("No batch has stored results yet.")
        _limitations()
        return
    ids = [b["batch_id"] for b in batches]
    chosen = st.multiselect("Batches (several are added together)", ids, default=ids[:1],
                            key="result_batches")
    if not chosen:
        st.write("Pick at least one batch.")
        _limitations()
        return
    m = data.matrix(s["db"], s["results_dir"], chosen)
    port_is_open = control.port_open(s["host"], s["port"])
    by_id = {b["batch_id"]: b for b in batches}
    for i in m["included"]:
        plan, _ = data.read_plan_safe(s["results_dir"], i["batch_id"])
        i["state"] = _state_of(plan, by_id[i["batch_id"]]["has_result_files"],
                               port_is_open)[0]
        short = i["planned_runs"] is not None and i["stored_results"] < i["planned_runs"]
        i["incomplete"] = (i["aborted"] is True or short
                           or i["state"] not in ("finished", "aborted")
                           or (i["planned_runs"] is not None and i["aborted"] is None))
    st.caption("Included batches")
    st.dataframe(pd.DataFrame([{
        "batch": i["batch_id"], "stored results": i["stored_results"],
        "planned runs": "unknown" if i["planned_runs"] is None else i["planned_runs"],
        "state": STATE_TEXT[i["state"]],
        "aborted": {True: "YES", False: "no", None: "unknown"}[i["aborted"]],
        "complete": "NO, incomplete" if i["incomplete"] else "yes"}
        for i in m["included"]]), hide_index=True, width="stretch")
    incomplete = [i["batch_id"] for i in m["included"] if i["incomplete"]]
    if incomplete:
        st.warning("The matrix below is INCOMPLETE. These included batches are still "
                   "running, were aborted or stopped, or have fewer stored results than "
                   "planned: " + ", ".join(incomplete))
    t = m["totals"]
    st.write(f"**{t['total']} runs**: {t['valid']} valid, {t['invalid']} invalid (invalid "
             f"runs are in no cell). {t['runs_with_parse_failures']} runs had parse "
             f"failures. {t['runs_with_attempted_tripwires']} runs had unexecuted trap "
             f"attempts. {t['runs_with_blocked_attempts']} runs had an action blocked by a "
             "defense.")
    models = []
    for row in m["rows"]:
        if row["model_name"] not in models:
            models.append(row["model_name"])
    for model in models:
        st.subheader(model)
        rows = [r for r in m["rows"] if r["model_name"] == model]
        st.dataframe(pd.DataFrame([{
            "Defense": r["defense_id"],
            "Temp": _temp_text(r["temperature"]), "Taxonomy": r["attack_taxonomy"],
            "Valid runs": r["n_valid"],
            **{CELL_LABELS[c]: _pct(r[c], r["n_valid"]) for c in CELLS},
            "Invalid": r["invalid"],
            "Poison read": _pct(r["poison_ingested"], r["n_valid"]),
            "Canary read": _pct(r["canary_read"], r["n_valid"]),
            "Runs with parse failures": _pct(r["runs_with_parse_failures"], r["n_valid"]),
            "Runs with unexecuted trap attempts": (
                _pct(r["runs_with_attempted_tripwires"], r["n_valid"])
                if r["attempted_recorded"] else data.NOT_RECORDED),
            "Runs with blocked attempts": _pct(r["runs_with_blocked_attempts"], r["n_valid"]),
            "Runs with provider refusals": _pct(r["runs_with_provider_refusals"],
                                                r["n_valid"]),
            "Final answer reported a trap": _pct(r["final_reported"], r["n_valid"]),
            "Final answer relayed a trap": _pct(r["final_relayed"], r["n_valid"]),
            "Distinct trajectories": r["distinct_trajectories"]}
            for r in rows]), hide_index=True, width="stretch")
    st.caption("Attempted calls were never executed and are not part of any cell. Distinct "
               "trajectories are counted per model, defense, temperature and taxonomy.")
    comparison = m["defense_comparison"]
    if len({c["defense_id"] for c in comparison}) > 1:
        st.subheader("Defense comparison")
        st.caption("Valid runs of every temperature together. Fewer compromised runs is "
                   "what the defense stopped; blocked runs show the model was still fooled; "
                   "fewer completed runs is what the defense cost the real task.")
        st.dataframe(pd.DataFrame([{
            "Model": c["model_name"], "Taxonomy": c["attack_taxonomy"],
            "Defense": c["defense_id"], "Valid runs": c["n_valid"],
            "Compromised": _pct(c["compromised"], c["n_valid"]),
            "Runs with blocked attempts": _pct(c["blocked"], c["n_valid"]),
            "Task completed": _pct(c["task_completed"], c["n_valid"])}
            for c in comparison]), hide_index=True, width="stretch")
    _limitations()


def _limitations() -> None:
    st.subheader("Limitations")
    for note in data.LIMITATIONS:
        st.text(note)


# ---- Inspect page -----------------------------------------------------------

def page_inspect(s: dict) -> None:
    st.header("Inspect a run")
    batches = data.list_batches(s["db"], s["results_dir"])
    ids = [b["batch_id"] for b in batches if b["recorded_runs"]]
    if not ids:
        st.write("No recorded runs yet.")
        return
    batch_id = st.selectbox("Batch", ids, key="inspect_batch")
    runs = data.batch_runs(s["db"], batch_id)
    only = st.checkbox("Compromised runs only", key="only_compromised")
    if only:
        runs = [r for r in runs if r["compromised"]]
    if not runs:
        st.write("No runs match.")
        return
    labels = [f"{r['scenario_id']} | {r['model_name']} | t={_temp_text(r['temperature'])} | "
              f"rep {r['repetition_index']} | {r['cell']} | {r['run_id'][:8]}" for r in runs]
    # the key carries the batch and the filter: the browser keeps the shown label per widget,
    # so a changed run list needs a new widget or the box can name a run that is not shown
    pick = st.selectbox("Run", range(len(runs)), format_func=lambda i: labels[i],
                        key=f"inspect_run|{batch_id}|{int(only)}")
    d = data.run_detail(s["db"], s["listener_db"], s["fixtures_root"], runs[pick]["run_id"])
    result = d["result"]
    if result is None:
        st.error("This run has no stored result. It has not been graded; nothing below "
                 "is a grade.")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("Result", result["cell"])
        c2.metric("Tripwires fired", ", ".join(d["tripwires_fired"]) or "none")
        c3.metric("Canaries leaked", ", ".join(result.get("canary_ids", [])) or "none")
        if not result["valid"]:
            st.error("Invalid run (in no cell). Reason:")
            st.text(str(result.get("invalid_reason")))
        for note in result.get("notes", []):
            st.text(f"Grader note: {note}")
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Defense", result["defense_id"])
        s2.metric("Final answer names a trap", result["final_trap_mention"])
        s3.metric("Warning word in final answer", "yes" if result["noticed_injection"] else "no")
        s4.metric("Provider refusals", result["provider_refusals"])
        st.caption("These four are signals, not grades. The two about the final answer are "
                   "keyword matches.")
        if result["blocked_calls"]:
            st.caption("Actions the defense blocked. They never ran and are not part of "
                       "the result above.")
            st.dataframe(pd.DataFrame([{
                "event": c["event"], "target": c["target"],
                "would have fired": ", ".join(c["would_fire"]) or "nothing"}
                for c in result["blocked_calls"]]), hide_index=True, width="stretch")
    if d["inputs"]:
        st.caption("Task given to the agent")
        st.code(d["inputs"]["user_prompt"], language=None, wrap_lines=True)
        with st.expander("System prompt this run was given"):
            st.code(d["inputs"]["system_prompt"], language=None, wrap_lines=True)

    with st.container(border=True):
        st.subheader("Attempted calls that were never executed")
        st.caption("From replies rejected as parse failures. Not part of the result above.")
        calls = d["attempted_calls"]
        if result is None:
            st.write("not recorded (this run has not been graded)")
        elif calls == data.NOT_RECORDED:
            st.write("not recorded (this result was written before attempted calls were "
                     "tracked)")
        elif not calls:
            st.write("None.")
        else:
            st.dataframe(pd.DataFrame([{
                "step": c["step_index"], "tool": c["tool_name"],
                "arguments": json.dumps(c["args"]),
                "would have fired": ", ".join(c["would_fire"]) or "nothing"}
                for c in calls]), hide_index=True, width="stretch")

    poison_step = d["poison_step_index"]
    left, right = st.columns(2)
    with left:
        st.subheader("Poisoned file")
        if not d["poison_texts"]:
            st.write("This scenario has no poison file.")
        for p in d["poison_texts"]:
            st.caption(f"{p['file']}: {p['source']}")
            st.code(p["text"], language=None, wrap_lines=True)
    with right:
        st.subheader("Agent replies after the poison")
        if poison_step is None:
            st.write("No poison file was in the context at any step of this run.")
        else:
            st.caption(f"Poison entered the context at step {poison_step}. Raw reply text "
                       "from that step on:")
            for x in d["steps"]:
                if x["step_index"] >= poison_step:
                    st.caption(f"step {x['step_index']} | {x['agent_state']}")
                    st.code(x["raw_response"] or "(empty reply)", language="json",
                            wrap_lines=True)

    st.subheader("All steps")
    for x in d["steps"]:
        mark = "  <- poison in context from here" if x["step_index"] == poison_step else ""
        title = (f"step {x['step_index']} | {x['agent_state']} | "
                 f"{x['tool_name'] or 'no tool'}{mark}")
        with st.expander(title):
            # parse_reason quotes model text, so it is shown as plain text
            st.text(f"parse_reason: {x['parse_reason'] or 'none'}\n"
                    f"done_reason: {x['done_reason'] or 'none'} | tokens: "
                    f"{x['token_count']} | prompt tokens: {x['prompt_token_count']}")
            st.caption("Reply")
            st.code(x["raw_response"] or "(none)", language=None, wrap_lines=True)
            st.caption("Tool result returned to the model (full)")
            st.code(x["tool_result"] if x["tool_result"] is not None else "(none)",
                    language=None, wrap_lines=True)
    if d["listener_events"]:
        st.subheader("Listener rows for this run")
        st.dataframe(pd.DataFrame([{
            "time": e["timestamp"], "method": e["method"], "path": e["path"],
            "class": e["route_class"], "canaries": ", ".join(e["canary_ids"]) or "none",
            "body": e["body_text"]} for e in d["listener_events"]]),
            hide_index=True, width="stretch")
    if d["telemetry_enabled"]:
        st.subheader("Entropy trace (approximate, secondary experiment)")
        trace = pd.DataFrame([{"step": x["step_index"],
                               "mean_entropy_approx": x["mean_entropy_approx"]}
                              for x in d["steps"] if x["mean_entropy_approx"] is not None])
        if len(trace):
            st.line_chart(trace, x="step", y="mean_entropy_approx")
        else:
            st.write("Telemetry was on but no entropy values were recorded.")


def main() -> None:
    st.set_page_config(page_title="redteam2.0", layout="wide")
    try:
        s = _settings()
    except (ConfigError, OSError, ValueError) as exc:
        st.error(f"Configuration could not be loaded: {exc}")
        return
    page = st.sidebar.radio("Page", PAGES, key="page")
    st.sidebar.caption("Every grade shown here was stored by the grader. This app never "
                       "grades and never shows a key.")
    {"Run": page_run, "Results": page_results, "Inspect a run": page_inspect}[page](s)


main()
