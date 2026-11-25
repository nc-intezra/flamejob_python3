"""Dashboard serving. Port of web.rs render_dashboard + the dashboard listener.

The SPA (``dashboard/dashboard.html``) is copied **verbatim** from the Rust repo
and served with its ``"__FJCFG__"`` placeholder replaced by the runtime config
blob — identical field set to the Rust server, so the page behaves the same.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from .config import Config

# Matches routes.rs MAX_FILE_UPLOAD_BYTES (8 GiB) for the ingest pane's per-file gauge.
MAX_FILE_UPLOAD_BYTES = 8 * 1024 * 1024 * 1024

_DASHBOARD_PATH = Path(__file__).resolve().parents[2] / "dashboard" / "dashboard.html"


@lru_cache(maxsize=1)
def _dashboard_html() -> str:
    return _DASHBOARD_PATH.read_text(encoding="utf-8")


def render_dashboard(cfg: Config) -> str:
    api_port = 8443
    tail = cfg.server.bind.rsplit(":", 1)[-1]
    if tail.isdigit():
        api_port = int(tail)
    blob = {
        "apiBase": cfg.web.api_base,  # str or None → JSON null
        "apiPort": api_port,
        "theme": cfg.web.theme,
        "version": _version(),
        "uploadLimit": MAX_FILE_UPLOAD_BYTES,
    }
    return _dashboard_html().replace('"__FJCFG__"', json.dumps(blob))


def _version() -> str:
    import importlib.metadata

    try:
        return importlib.metadata.version("flamejob")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def dashboard_router(cfg: Config) -> APIRouter:
    router = APIRouter()
    page = render_dashboard(cfg)

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> str:
        return page

    return router
