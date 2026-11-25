from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from flamejob_server.config import AuthCfg, Config

_FIXTURES = Path(__file__).resolve().parents[1] / "interop" / "fixtures" / "rust_fixtures.json"
_DEFAULT_RUST_BIN = (
    Path(__file__).resolve().parents[1]
    / "interop"
    / "rust-fixture"
    / "target"
    / "release"
    / "gen-fixtures"
)


@pytest.fixture(scope="session")
def rust_fixtures() -> dict:
    if not _FIXTURES.is_file():
        pytest.skip(f"rust fixtures not generated at {_FIXTURES}")
    return json.loads(_FIXTURES.read_text())


@pytest.fixture
def config_with_secret():
    def _make(secret: str) -> Config:
        # init values win over env/TOML, so the test secret is deterministic.
        return Config(auth=AuthCfg(jwt_secret=secret, token_ttl_hours=1))

    return _make


@pytest.fixture(scope="session")
def rust_verifier() -> str:
    path = os.environ.get("FLAMEJOB_RUST_BIN", str(_DEFAULT_RUST_BIN))
    if not Path(path).is_file():
        pytest.skip(f"rust verifier binary not available at {path}")
    return path
