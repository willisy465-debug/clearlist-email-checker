"""Clearlist web app."""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.cloud_probe import parse_socks5_url
from app.verifier import begin_job, check_syntax, default_helo, verify_email

log = logging.getLogger("clearlist")
BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
EXECUTOR = ThreadPoolExecutor(max_workers=24, thread_name_prefix="clearlist")


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    EXECUTOR.shutdown(wait=False, cancel_futures=True)


app = FastAPI(title="Clearlist", lifespan=lifespan)


class VerifyRequest(BaseModel):
    emails: list[str] = Field(min_length=1, max_length=500)
    smtp: bool = True
    catch_all: bool = True
    helo: str = ""
    mail_from: str = ""
    force_smtp: bool = False
    proxy_url: str = ""
    api_url: str = ""
    api_key: str = ""
    fast_bulk: bool = False


@app.middleware("http")
async def no_store(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "helo": default_helo()}


@app.post("/api/verify")
async def verify(body: VerifyRequest) -> dict:
    emails = [item.strip() for item in body.emails if item.strip()]
    if not emails:
        raise HTTPException(status_code=400, detail="Add at least one address.")
    helo = _validate_helo(body.helo)
    mail_from = _validate_mail_from(body.mail_from)
    proxy_url = _validate_proxy_url(body.proxy_url)
    api_url = _validate_api_url(body.api_url)
    job = begin_job(
        smtp=body.smtp,
        catch_all=body.catch_all and body.smtp,
        helo=helo,
        mail_from=mail_from,
        force_smtp=body.force_smtp,
        proxy_url=proxy_url,
        api_url=api_url,
        api_key=body.api_key.strip(),
        fast_bulk=body.fast_bulk or len(emails) >= 60,
    )
    log.info("batch size=%s smtp_mode=%s", len(emails), job.smtp_mode)
    loop = asyncio.get_running_loop()
    results = await asyncio.gather(
        *[loop.run_in_executor(EXECUTOR, partial(verify_email, email, job)) for email in emails]
    )
    return {
        "results": results,
        "smtp_network": job.smtp_mode,
        "smtp_network_detail": job.smtp_mode_detail,
        "checked": len(results),
    }


def _validate_proxy_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if any(char in value for char in "\r\n\x00 "):
        raise HTTPException(status_code=400, detail="SOCKS5 proxy URL cannot contain spaces.")
    try:
        parse_socks5_url(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return value


def _validate_api_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if any(char in value for char in "\r\n\x00 "):
        raise HTTPException(status_code=400, detail="Verification API URL cannot contain spaces.")
    if not (value.startswith("https://") or value.startswith("http://")):
        raise HTTPException(
            status_code=400,
            detail="Verification API URL must start with https:// or http://.",
        )
    return value


def _validate_helo(value: str) -> str:
    value = value.strip().rstrip(".")
    if any(char in value for char in "\r\n\x00 "):
        raise HTTPException(status_code=400, detail="HELO hostname cannot contain spaces.")
    if not value:
        return default_helo()
    if len(value) > 253 or not value.replace(".", "").replace("-", "").isalnum():
        raise HTTPException(
            status_code=400,
            detail="HELO hostname can only contain letters, numbers, dots, and hyphens.",
        )
    return value


def _validate_mail_from(value: str) -> str:
    value = value.strip()
    if any(char in value for char in "\r\n\x00"):
        raise HTTPException(status_code=400, detail="MAIL FROM contains invalid characters.")
    if not value:
        return ""
    value = value.strip("<>").strip()
    syntax = check_syntax(value)
    if not syntax["ok"]:
        raise HTTPException(
            status_code=400,
            detail="MAIL FROM must be a valid email address, or left empty for a null sender.",
        )
    return syntax["email"]


app.mount("/static", StaticFiles(directory=STATIC), name="static")
