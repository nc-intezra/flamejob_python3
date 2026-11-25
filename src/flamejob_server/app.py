"""FastAPI application factory + entrypoint. Phase 1 read surface.

Wires the asyncpg pool over the app lifespan, CORS from ``[web].allowed_origins``,
the RFC-7807 error handlers, and the read routers. FastAPI generates the OpenAPI
document (replacing utoipa) at ``/openapi.json`` and the docs UI at ``/docs``.
"""

from __future__ import annotations

import importlib.metadata
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from flamejob_db import create_pool

from .config import Config
from .crypto import Cipher, key_from_config
from .dashboard import dashboard_router
from .errors import install_error_handlers
from .hub import AgentHub
from .routes_agent import router as agent_router
from .routes_auth import router as auth_router
from .routes_files import router as files_router
from .routes_hashlists import router as hashlists_router
from .routes_job_writes import router as job_writes_router
from .routes_jobs import router as jobs_router
from .routes_telemetry import router as telemetry_router


def _version() -> str:
    try:
        return importlib.metadata.version("flamejob")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or Config()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        pool = await create_pool(cfg.database.dsn, cfg.database.max_connections)
        app.state.pool = pool
        app.state.cfg = cfg
        try:
            yield
        finally:
            await pool.close()

    app = FastAPI(title="flamejob", version=_version(), lifespan=lifespan)
    app.state.cfg = cfg
    # The singular control-plane brain + the data-at-rest cipher live on app state.
    app.state.hub = AgentHub()
    app.state.cipher = Cipher(key_from_config(cfg))

    origins = cfg.web.allowed_origins or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=bool(cfg.web.allowed_origins),
        allow_methods=["*"],
        allow_headers=["*"],
    )

    install_error_handlers(app)

    @app.get("/healthz", tags=["meta"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth_router)
    app.include_router(jobs_router)
    app.include_router(job_writes_router)
    app.include_router(hashlists_router)
    app.include_router(files_router)
    app.include_router(telemetry_router)
    app.include_router(agent_router)
    app.include_router(dashboard_router(cfg))
    return app


app = create_app()


def main() -> None:
    import uvicorn

    cfg = Config()
    host, _, port = cfg.server.bind.partition(":")
    uvicorn.run(app, host=host or "0.0.0.0", port=int(port or "8443"))  # noqa: S104


if __name__ == "__main__":
    main()
