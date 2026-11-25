"""Authentication primitives. Port of ``flamejob-server/src/auth.rs``.

JWT stays **HS256 + shared secret** for the duration of the strangler migration
(both servers verify each other's tokens, M1->M2); the algorithm is pinned
explicitly on decode so the accepted set is never open to confusion. The Phase-7
cutover swaps the scheme to EdDSA/Ed25519 + a per-user token epoch (plan D8/§6).

Argon2id is configured to the Rust ``Argon2::default()`` parameters
(``m=19456, t=2, p=1, v=19``, 32-byte hash, 16-byte salt) so Python-minted
hashes carry the same params; verification of either side's PHC strings works
regardless, since the parameters are read from the string.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import Argon2Error, VerifyMismatchError
from pydantic import BaseModel

from flamejob_core import Capability, Role, roles_have

from .config import Config

_ALG = "HS256"

_PH = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


class Claims(BaseModel):
    sub: UUID
    username: str
    roles: list[Role]
    exp: int
    iat: int


@dataclass
class AuthUser:
    id: UUID
    username: str
    roles: list[Role]

    def require(self, cap: Capability) -> None:
        if not roles_have(self.roles, cap):
            raise PermissionError(f"missing capability {cap.name}")

    def require_any(self, caps: list[Capability]) -> None:
        if not any(roles_have(self.roles, c) for c in caps):
            raise PermissionError(f"missing any of capabilities {[c.name for c in caps]}")


def issue_token(
    cfg: Config, user_id: UUID, username: str, roles: list[Role]
) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=max(cfg.auth.token_ttl_hours, 1))
    payload = {
        "sub": str(user_id),
        "username": username,
        "roles": [r.value for r in roles],
        "exp": int(exp.timestamp()),
        "iat": int(now.timestamp()),
    }
    token = jwt.encode(payload, cfg.auth.jwt_secret, algorithm=_ALG)
    return token, exp


def decode_token(cfg: Config, token: str) -> AuthUser:
    """Verify an HS256 token and return the authenticated user.

    Raises ``jwt.InvalidTokenError`` (incl. expiry) on any failure.
    """
    data = jwt.decode(token, cfg.auth.jwt_secret, algorithms=[_ALG])
    claims = Claims.model_validate(data)
    return AuthUser(id=claims.sub, username=claims.username, roles=claims.roles)


def hash_password(pw: str) -> str:
    return _PH.hash(pw)


def verify_password(pw: str, phc_hash: str) -> bool:
    try:
        return _PH.verify(phc_hash, pw)
    except (VerifyMismatchError, Argon2Error, ValueError):
        return False


def api_key_hash(key: str) -> str:
    """Hex SHA-256 of an API key's full secret — what we store and look up by."""
    return hashlib.sha256(key.encode()).hexdigest()
