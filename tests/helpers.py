"""Shared test helpers (importable via the ``tests`` dir on pytest's pythonpath)."""

from __future__ import annotations

from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def swap_db(dsn: str, dbname: str) -> str:
    """Return ``dsn`` with its database path replaced by ``dbname``."""
    base, _, _ = dsn.rpartition("/")
    return f"{base}/{dbname}"
