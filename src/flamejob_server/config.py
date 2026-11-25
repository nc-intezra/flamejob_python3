"""Runtime configuration. Port of ``flamejob-server/src/config.rs``.

Mirrors the Rust figment layering (defaults -> TOML file -> ``FJ_`` env with
``__`` nesting; env wins) with pydantic-settings, and keeps the same defaults so
a deployment's existing ``flamejob.toml`` / ``FJ_*`` env loads unchanged.
"""

from __future__ import annotations

import os
import socket
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)


def _hostname() -> str:
    try:
        return socket.gethostname() or "local-host"
    except OSError:
        return "local-host"


class ServerCfg(BaseModel):
    bind: str = "0.0.0.0:8443"
    tls_cert: str | None = None
    tls_key: str | None = None


class DatabaseCfg(BaseModel):
    mode: str = "local"
    dsn: str = "postgres://flamejob@localhost/flamejob"
    max_connections: int = 10


class AuthCfg(BaseModel):
    jwt_secret: str = "dev-insecure-change-me"  # noqa: S105  dev default; FJ-001 startup guard rejects it
    token_ttl_hours: int = 1


class HashcatCfg(BaseModel):
    binary: str = "/usr/bin/hashcat"
    data_dir: str = "/var/lib/flamejob"
    workload: int = 3
    files_quota_bytes: int = 0  # 0 = unlimited


class CryptoCfg(BaseModel):
    plaintext_key_file: str | None = None


class SchedulerCfg(BaseModel):
    chunk_size: int = 50_000_000
    max_chunks: int = 500
    runner: Literal["local", "remote"] = "local"
    local_parallelism: int = 1
    max_concurrent_jobs: int = 8
    local_agent_name: str = Field(default_factory=_hostname)


class TelemetryCfg(BaseModel):
    enabled: bool = True
    sample_interval_secs: int = 5
    history_limit: int = 500


class WebCfg(BaseModel):
    enabled: bool = True
    bind: str = "0.0.0.0:9443"
    tls_cert: str | None = None
    tls_key: str | None = None
    api_base: str | None = None
    theme: str = "mission"
    https_bind: str = "0.0.0.0:443"
    allowed_origins: list[str] = Field(default_factory=list)


class Config(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FJ_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    server: ServerCfg = Field(default_factory=ServerCfg)
    database: DatabaseCfg = Field(default_factory=DatabaseCfg)
    auth: AuthCfg = Field(default_factory=AuthCfg)
    hashcat: HashcatCfg = Field(default_factory=HashcatCfg)
    crypto: CryptoCfg = Field(default_factory=CryptoCfg)
    scheduler: SchedulerCfg = Field(default_factory=SchedulerCfg)
    telemetry: TelemetryCfg = Field(default_factory=TelemetryCfg)
    web: WebCfg = Field(default_factory=WebCfg)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Precedence mirrors figment: env > TOML > defaults. (init_settings lets
        # tests/callers override explicitly and wins over all.)
        path = os.environ.get("FLAMEJOB_CONFIG", "/etc/flamejob/flamejob.toml")
        toml = TomlConfigSettingsSource(settings_cls, toml_file=path)
        return (init_settings, env_settings, toml)
