"""HTTP error model → RFC 7807 problem+json. Port of ``error.rs``.

Mirrors ``AppError::parts()`` status/title mapping. **FJ-015**: internal/driver
error text is logged server-side with a correlation id and never returned to the
client — the 500 body is generic.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from flamejob_api.schemas import Problem

log = logging.getLogger("flamejob.error")

_PROBLEM_MEDIA = "application/problem+json"


class AppError(Exception):
    status: int = 500
    title: str = "Internal Server Error"
    type_uri: str = "about:blank"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.title)
        self.detail = detail


class Unauthorized(AppError):
    status, title = 401, "Unauthorized"


class Forbidden(AppError):
    status, title = 403, "Forbidden"


class NotFound(AppError):
    status, title = 404, "Not Found"


class TooManyRequests(AppError):
    status, title = 429, "Too Many Requests"


class InsufficientStorage(AppError):
    status, title = 507, "Insufficient Storage"


class Internal(AppError):
    status, title = 500, "Internal Server Error"


def _problem(
    status: int, title: str, detail: str | None, type_uri: str = "about:blank"
) -> JSONResponse:
    body = Problem(type_uri=type_uri, title=title, status=status, detail=detail)
    return JSONResponse(
        status_code=status,
        content=body.model_dump(mode="json", by_alias=True),
        media_type=_PROBLEM_MEDIA,
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_req: Request, exc: AppError) -> JSONResponse:
        # Internal errors never leak their detail to the client (FJ-015).
        if exc.status >= 500:
            cid = uuid.uuid4().hex[:12]
            log.error("internal error [%s]: %s", cid, exc.detail or exc)
            return _problem(exc.status, exc.title, f"internal error (ref {cid})")
        return _problem(exc.status, exc.title, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def _validation(_req: Request, exc: RequestValidationError) -> JSONResponse:
        return _problem(422, "Unprocessable Entity", "request validation failed")

    @app.exception_handler(Exception)
    async def _unhandled(_req: Request, exc: Exception) -> JSONResponse:
        cid = uuid.uuid4().hex[:12]
        log.exception("unhandled error [%s]", cid)
        return _problem(500, "Internal Server Error", f"internal error (ref {cid})")
