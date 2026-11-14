"""Run log schema: column lists, column types and DDL (CLAUDE.md 4.4)."""

IDENTITY_COLUMNS = ("run_id", "timestamp", "model_name", "scenario_id",
                    "attack_taxonomy", "repetition_index", "temperature")

STEP_COLUMNS = IDENTITY_COLUMNS + (
    "step_index", "agent_state", "tool_name", "tool_args_json",
    "tool_call_parse_failed", "raw_response", "tool_result", "poison_ingested",
    "token_count", "latency_ms", "tokens_per_sec", "mean_logprob", "min_logprob",
    "std_logprob", "mean_entropy_approx", "max_entropy_approx",
    "entropy_spike_delta", "tool_name_logprob")

RUN_COLUMNS = ("run_id", "batch_id", "model_name", "scenario_id", "attack_taxonomy",
               "repetition_index", "temperature", "telemetry_enabled", "started_at",
               "ended_at", "status", "invalid_reason", "stop_reason",
               "final_response", "steps", "parse_failures", "poison_ingested",
               "ctx_tripwire_canary_read", "ctx_tripwire_unauth_tool_call")

AGENT_STATES = ("PRE_POISON", "POST_POISON_INGESTION", "TOOL_DECISION",
                "FINAL_RESPONSE", "PARSE_FAILURE")
RUN_STATUSES = ("completed", "invalid")

BOOL_COLUMNS = ("tool_call_parse_failed", "poison_ingested", "telemetry_enabled",
                "ctx_tripwire_canary_read", "ctx_tripwire_unauth_tool_call")
INTEGER_COLUMNS = ("step_index", "repetition_index", "token_count", "steps",
                   "parse_failures")
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


DDL = (
    "CREATE TABLE IF NOT EXISTS steps (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    "
    + _columns_ddl(STEP_COLUMNS) + "\n)",
    "CREATE INDEX IF NOT EXISTS idx_steps_run ON steps (run_id)",
    "CREATE TABLE IF NOT EXISTS tool_events (\n"
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    run_id TEXT NOT NULL,\n    timestamp TEXT NOT NULL,\n"
    "    event TEXT NOT NULL,\n    detail_json TEXT NOT NULL\n)",
    "CREATE INDEX IF NOT EXISTS idx_tool_events_run ON tool_events (run_id)",
    "CREATE TABLE IF NOT EXISTS runs (\n    "
    + _columns_ddl(RUN_COLUMNS).replace("run_id TEXT", "run_id TEXT PRIMARY KEY", 1)
    + "\n)",
)
