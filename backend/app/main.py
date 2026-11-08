"""FastAPI entrypoint: GitHub webhook receiver + dashboard API.

Run:  uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import router as api_router
from app.config import get_settings
from app.db import dispose_db, init_db
from app.github_app import verify_webhook_signature
from app.migrations import migrate
from app.pipeline import (
    handle_installation_event,
    job_from_pull_request,
    job_from_push,
    run_scan,
)

settings = get_settings()
logging.basicConfig(level=settings.log_level.upper(),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("zeroday")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await init_db()
    await migrate()
    if not settings.github_webhook_secret:
        logger.warning("GITHUB_WEBHOOK_SECRET is not set: all webhooks will be rejected")
    if not settings.llm_configured:
        logger.warning("No LLM API key configured: running deterministic-only scans")
    yield
    await dispose_db()


app = FastAPI(title="0 Days Since API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["Authorization", "X-GitHub-Login", "Last-Event-ID"],
)
app.include_router(api_router)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "llm": settings.llm_configured, "model": settings.llm_model,
            "github_app": bool(settings.github_app_id)}


MAX_WEBHOOK_BYTES = 25 * 1024 * 1024  # GitHub caps payloads at 25 MB


@app.post("/api/webhooks/github", status_code=202)
async def github_webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_event: Annotated[str, Header()],
    x_github_delivery: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await request.body()
    if len(body) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")
    # Fail closed: without a configured secret nothing is accepted.
    if not verify_webhook_signature(settings.github_webhook_secret, body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="invalid signature")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid JSON") from exc

    event = x_github_event
    queued: str | None = None
    if event == "ping":
        return JSONResponse({"ok": True, "zen": payload.get("zen")}, status_code=200)
    if event in {"installation", "installation_repositories"}:
        background.add_task(handle_installation_event, event, payload)
        queued = "installation"
    elif event == "push":
        job = job_from_push(payload, x_github_delivery)
        if job is not None:
            background.add_task(run_scan, job)
            queued = "scan"
    elif event == "pull_request":
        job = job_from_pull_request(payload, x_github_delivery)
        if job is not None:
            background.add_task(run_scan, job)
            queued = "scan"
    logger.info("webhook %s (%s) -> %s", event, x_github_delivery, queued or "ignored")
    return JSONResponse({"accepted": True, "queued": queued}, status_code=202)
