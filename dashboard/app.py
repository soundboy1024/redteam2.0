"""redteam2.0 control panel and inspector (CLAUDE.md 4.8 and Phase 4).

Three pages: Run, Results, Inspect a run. This app never grades: every grade shown
is a row the grader stored. Model text is untrusted and is only ever shown through
st.code, st.text or a dataframe cell, never as HTML.

Launch: run_dashboard.bat   (port 8503)
"""
import json
import os
import pathlib
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
STATE_TEXT = {"running": "RUNNING", "finished": "finished", "aborted": "ABORTED",
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


def _batch_state(s: dict, batch: dict, port_is_open: bool) -> str:
    plan, _ = data.read_plan_safe(s["results_dir"], batch["batch_id"])
    return control.batch_state(plan, port_is_open, batch["has_result_files"])


def _running_batch(s: dict, batches: list[dict], port_is_open: bool) -> str | None:
    for b in batches:
        if _batch_state(s, b, port_is_open) == "running":
            return b["batch_id"]
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

    batches = data.list_batches(s["db"], s["results_dir"])
    port_is_open = control.port_open(s["host"], s["port"])
    running = _running_batch(s, batches, port_is_open)

    problem = temp_problem
    if not models:
        problem = "pick at least one model"
    elif not scenario_ids:
        problem = "pick at least one scenario"
    plan = None
    command = control.build_command(sys.executable, models, scenario_ids, temperatures,
                                    int(n_runs), batch_id.strip(), s["config_path"])
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
        blocker = f"batch {running} is running; one batch at a time"
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
            st.success(f"Started {batch_id.strip()}. Console output: {console}")
    confirm = b3.checkbox("I want to stop the running batch", key="confirm_stop",
                          disabled=running is None)
    if b2.button("Stop", disabled=not (running and confirm), key="stop"):
        plan_running, _ = data.read_plan_safe(s["results_dir"], running)
        try:
            out = control.stop_batch(plan_running, str(ROOT), sys.executable, s["host"],
                                     s["port"], s["config_path"])
        except ValueError as exc:
            st.error(f"Not stopped: {exc}")
        else:
            st.warning(f"Stopped {running}. Process killed: {out['killed']}. "
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
    state = control.batch_state(p["plan"], port_is_open, p["has_result_files"])
    planned = p["planned_runs"]
    st.subheader(f"{batch_id}: {STATE_TEXT[state]}")
    if p["plan_problem"]:
        st.error(f"batch.json could not be read: {p['plan_problem']}")
    st.write(f"**{p['recorded_runs']} / {planned if planned is not None else 'unknown'}** "
             "runs recorded")
    if planned:
        st.progress(min(1.0, p["recorded_runs"] / planned))
    if p["plan"] and p["plan"].get("abort_reason"):
        st.error(f"Abort reason: {p['plan']['abort_reason']}")
    if state == "stopped_without_results":
        st.error("This batch stopped without writing results. Nothing about it is a "
                 "result until it is regraded.")
        if st.button("Regrade this batch", key=f"regrade_{batch_id}"):
            out = control.regrade_batch(batch_id, str(ROOT), sys.executable, s["config_path"])
            st.write(f"Regrade exit code: {out['regrade_exit']}")
            st.code(out["regrade_output"], language=None)
    cur = p["current"]
    if cur and state == "running":
        st.write(f"**Now:** {cur['scenario_id']} | {cur['model_name']} | "
                 f"temperature {_temp_text(cur['temperature'])} | "
                 f"repetition {cur['repetition_index']}")
        st.caption("Latest steps of the run in progress")
        st.dataframe(pd.DataFrame([{
            "step": x["step_index"], "state": x["agent_state"], "tool": x["tool_name"],
            "arguments": x["tool_args_json"], "parse reason": x["parse_reason"]}
            for x in cur["last_steps"]]), hide_index=True, width="stretch")
    elif p["unrecorded_run_ids"] and state != "running":
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
    st.caption("Included batches")
    st.dataframe(pd.DataFrame([{
        "batch": i["batch_id"], "stored results": i["stored_results"],
        "planned runs": "unknown" if i["planned_runs"] is None else i["planned_runs"],
        "aborted": {True: "YES, incomplete", False: "no", None: "unknown"}[i["aborted"]]}
        for i in m["included"]]), hide_index=True, width="stretch")
    if any(i["aborted"] for i in m["included"]):
        st.warning("At least one included batch was aborted, so the matrix is incomplete.")
    t = m["totals"]
    st.write(f"**{t['total']} runs**: {t['valid']} valid, {t['invalid']} invalid (invalid "
             f"runs are in no cell). {t['runs_with_parse_failures']} runs had parse "
             f"failures. {t['runs_with_attempted_tripwires']} runs had unexecuted trap "
             "attempts.")
    models = []
    for row in m["rows"]:
        if row["model_name"] not in models:
            models.append(row["model_name"])
    for model in models:
        st.subheader(model)
        rows = [r for r in m["rows"] if r["model_name"] == model]
        st.dataframe(pd.DataFrame([{
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
            "Distinct trajectories": r["distinct_trajectories"]}
            for r in rows]), hide_index=True, width="stretch")
    st.caption("Attempted calls were never executed and are not part of any cell. Distinct "
               "trajectories are counted per model, temperature and taxonomy.")
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
    pick = st.selectbox("Run", range(len(runs)), format_func=lambda i: labels[i],
                        key="inspect_run")
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
            st.error(f"Invalid run: {result.get('invalid_reason')}")
        for note in result.get("notes", []):
            st.caption(f"Grader note: {note}")
    if d["inputs"]:
        st.caption("Task given to the agent")
        st.code(d["inputs"]["user_prompt"], language=None, wrap_lines=True)

    with st.container(border=True):
        st.subheader("Attempted calls that were never executed")
        st.caption("From replies rejected as parse failures. Not part of the result above.")
        calls = d["attempted_calls"]
        if calls == data.NOT_RECORDED:
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
            st.write(f"parse_reason: {x['parse_reason'] or 'none'} | done_reason: "
                     f"{x['done_reason'] or 'none'} | tokens: {x['token_count']} | "
                     f"prompt tokens: {x['prompt_token_count']}")
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
