"""Run log schema: column lists, column types and DDL (CLAUDE.md 4.4)."""

# Stored as PRAGMA user_version. Bump on any column or table change; no migrations.
SCHEMA_VERSION = 2

IDENTITY_COLUMNS = ("run_id", "timestamp", "model_name", "scenario_id",
                    "attack_taxonomy", "repetition_index", "temperature")

STEP_COLUMNS = IDENTITY_COLUMNS + (
    "step_index", "agent_state", "tool_name", "tool_args_json",
    "tool_call_parse_failed", "raw_response", "tool_result", "poison_ingested",
    "token_count", "latency_ms", "tokens_per_sec", "mean_logprob", "min_logprob",
    "std_logprob", "mean_entropy_approx", "max_entropy_approx",
    "entropy_spike_delta", "tool_name_logprob",
    "parse_reason", "done_reason", "prompt_token_count")

RUN_COLUMNS = ("run_id", "batch_id", "model_name", "scenario_id", "attack_taxonomy",
               "repetition_index", "temperature", "telemetry_enabled", "started_at",
               "ended_at", "status", "invalid_reason", "stop_reason",
               "final_response", "steps", "parse_failures", "poison_ingested",
               "ctx_tripwire_canary_read", "ctx_tripwire_unauth_tool_call")

# One graded row per run, written by run_eval after grading. result_json holds the
# whole result row; the other columns are copies for querying.
RESULT_COLUMNS = ("run_id", "batch_id", "result_json", "model_name", "scenario_id",
                  "attack_taxonomy", "repetition_index", "valid", "cell", "compromised",
                  "task_completed", "tripwire_canary_read", "tripwire_unauth_tool_call",
                  "tripwire_canary_exfiltrated", "tripwire_honeypot_endpoint_hit",
                  "parse_failures", "poison_ingested")

# What each run was given, written by run_eval when the run starts.
RUN_INPUT_COLUMNS = ("run_id", "user_prompt", "system_prompt", "scenario_json")

AGENT_STATES = ("PRE_POISON", "POST_POISON_INGESTION", "TOOL_DECISION",
                "FINAL_RESPONSE", "PARSE_FAILURE")
RUN_STATUSES = ("completed", "invalid")

BOOL_COLUMNS = ("tool_call_parse_failed", "poison_ingested", "telemetry_enabled",
                "ctx_tripwire_canary_read", "ctx_tripwire_unauth_tool_call",
                "valid", "compromised", "task_completed", "tripwire_canary_read",
                "tripwire_unauth_tool_call", "tripwire_canary_exfiltrated",
                "tripwire_honeypot_endpoint_hit")
INTEGER_COLUMNS = ("step_index", "repetition_index", "token_count", "steps",
                   "parse_failures", "prompt_token_count")
REAL_COLUMNS = ("latency_ms", "tokens_per_sec", "mean_logprob", "min_logprob",
                "std_logprob", "mean_entropy_approx", "max_entropy_approx",
                "entropy_spike_delta", "tool_name_logprob", "temperature")


def sql_type(column: str) -> str:
    if column in BOOL_COLUMNS or column in INTEGER_COLUMNS:
        return "INTEGER"
    if column in REAL_COLUMNS:
        return "REAL"
    return "TEXT"


def _columns_ddl(columns) -> str:
    return ",\n    ".join(f"{c} {sql_type(c)}" for c in columns)


def _keyed_table(name: str, columns: tuple) -> str:
    return (f"CREATE TABLE IF NOT EXISTS {name} (\n    "
            + _columns_ddl(columns).replace("run_id TEXT", "run_id TEXT PRIMARY KEY", 1)
            + "\n)")


DDL = (
    "CREATE TABLE IF NOT EXISTS steps (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    "
    + _columns_ddl(STEP_COLUMNS) + "\n)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_steps_run_step ON steps (run_id, step_index)",
    "CREATE TABLE IF NOT EXISTS tool_events (\n"
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    run_id TEXT NOT NULL,\n    timestamp TEXT NOT NULL,\n"
    "    event TEXT NOT NULL,\n    detail_json TEXT NOT NULL\n)",
    "CREATE INDEX IF NOT EXISTS idx_tool_events_run ON tool_events (run_id)",
    _keyed_table("runs", RUN_COLUMNS),
    "CREATE INDEX IF NOT EXISTS idx_runs_batch ON runs (batch_id)",
    _keyed_table("results", RESULT_COLUMNS),
    "CREATE INDEX IF NOT EXISTS idx_results_batch ON results (batch_id)",
    _keyed_table("run_inputs", RUN_INPUT_COLUMNS),
)
