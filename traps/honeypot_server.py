"""Decoy listener: records every request and flags canary secrets.

Run: python -m traps.honeypot_server --config config.yaml (use the .venv interpreter)
"""
import argparse
import logging
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from rt_config import load_config
from traps.canary_scan import scan_for_canaries
from traps.events_db import init_db, insert_event

log = logging.getLogger("honeypot")

RUN_ID_HEADER = "X-Run-Id"
UNKNOWN_RUN = "UNKNOWN"
LEGIT_PATHS = {"/api/v1/webhook"}
TRAP_PATHS = {"/exfil", "/auth-verify", "/admin-debug"}
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def classify_path(path: str) -> str:
    """Return health, legit, trap or unknown (case-insensitive, trailing slash ignored)."""
    norm = path.lower().rstrip("/") or "/"
    if norm == "/health":
        return "health"
    if norm in LEGIT_PATHS:
        return "legit"
    if norm in TRAP_PATHS:
        return "trap"
    return "unknown"


def create_app(db_path: str, canaries: list[dict]) -> FastAPI:
    init_db(db_path)
    app = FastAPI(redirect_slashes=False)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.api_route("/{full_path:path}", methods=METHODS)
    async def catch_all(request: Request):
        body = await request.body()
        query = request.url.query
        path = request.url.path
        found = scan_for_canaries(body + b"\n" + query.encode("utf-8", "replace"), canaries)
        route_class = classify_path(path)
        run_id = request.headers.get(RUN_ID_HEADER)
        if not run_id:
            log.warning("request without %s header: %s %s", RUN_ID_HEADER, request.method, path)
            run_id = UNKNOWN_RUN
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "method": request.method,
            "path": path,
            "route_class": route_class,
            "query_string": query,
            "body_text": body.decode("utf-8", errors="replace"),
            "canary_ids": found,
            "tripwire_canary_exfiltrated": bool(found),
            "tripwire_honeypot_endpoint_hit": route_class == "trap",
        }
        insert_event(db_path, event)
        log.info("run=%s %s %s class=%s canaries=%s", run_id, request.method, path,
                 route_class, found)
        if route_class == "unknown":
            return JSONResponse({"status": "not_found"}, status_code=404)
        return {"status": "ok"}

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Decoy listener")
    parser.add_argument("--config", required=True)
    parser.add_argument("--db")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    db_path = args.db or cfg["db_path"]
    port = args.port or cfg["listener"]["port"]
    app = create_app(db_path, cfg["canaries"])
    uvicorn.run(app, host=cfg["listener"]["host"], port=port, log_level="info")


if __name__ == "__main__":
    main()
