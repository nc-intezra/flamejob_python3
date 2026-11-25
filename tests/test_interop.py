"""Phase-0 format-interop proofs.

These are the tests that underwrite the strangler migration: they prove the
Python port's crypto/auth produce and accept the *exact* artifacts the Rust
server does, so both can run against one shared database and one token/credential
population during the M1->M2 window.

Rust->Python directions run against artifacts emitted by the real Rust crates
(``interop/fixtures/rust_fixtures.json``). The Python->Rust direction pipes
Python-produced artifacts back through the compiled Rust ``verify`` binary.
"""

from __future__ import annotations

import hashlib
import json
import subprocess

import jwt
import pytest

from flamejob_core import Role
from flamejob_server.auth import api_key_hash, hash_password, issue_token, verify_password
from flamejob_server.crypto import Cipher

pytestmark = pytest.mark.interop


# ---- Rust -> Python ----------------------------------------------------------


def test_rust_jwt_verifies_in_python(rust_fixtures: dict) -> None:
    secret = rust_fixtures["jwt_secret"]
    # Signature + claims interop, independent of wall-clock (exp checked below).
    claims = jwt.decode(
        rust_fixtures["jwt"],
        secret,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )
    assert claims["sub"] == rust_fixtures["user_id"]
    assert claims["username"] == rust_fixtures["username"]
    assert claims["roles"] == rust_fixtures["roles"] == ["operator", "admin"]
    assert [Role(r) for r in claims["roles"]] == [Role.OPERATOR, Role.ADMIN]
    assert claims["exp"] == rust_fixtures["jwt_exp"]
    assert claims["iat"] == rust_fixtures["jwt_iat"]

    # A wrong secret must fail — proves we are really verifying the signature.
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            rust_fixtures["jwt"],
            "a-different-secret-of-sufficient-length-32+",
            algorithms=["HS256"],
            options={"verify_exp": False},
        )


def test_key_derivation_matches(rust_fixtures: dict) -> None:
    derived = hashlib.sha256(rust_fixtures["jwt_secret"].encode()).hexdigest()
    assert derived == rust_fixtures["aes_key_from_secret_hex"]


def test_rust_aes_record_decrypts_in_python(rust_fixtures: dict) -> None:
    # Record 1: key = SHA-256(jwt_secret) (dev-derivation path).
    key = bytes.fromhex(rust_fixtures["aes_key_from_secret_hex"])
    record = bytes.fromhex(rust_fixtures["aes_record_hex"])
    assert Cipher(key).decrypt(record) == rust_fixtures["aes_plaintext"].encode()

    # Record 2: explicit 32-byte key (key-file path).
    key2 = bytes.fromhex(rust_fixtures["aes_explicit_key_hex"])
    record2 = bytes.fromhex(rust_fixtures["aes_explicit_record_hex"])
    assert Cipher(key2).decrypt(record2) == rust_fixtures["aes_explicit_plaintext"].encode()

    # Tamper the tag -> authentication fails, returns None (never raises).
    bad = bytearray(record)
    bad[-1] ^= 0xFF
    assert Cipher(key).decrypt(bytes(bad)) is None


def test_rust_argon2_verifies_in_python(rust_fixtures: dict) -> None:
    assert verify_password(rust_fixtures["password"], rust_fixtures["argon2_hash"]) is True
    assert verify_password("not the password", rust_fixtures["argon2_hash"]) is False


def test_api_key_hash_matches(rust_fixtures: dict) -> None:
    assert api_key_hash(rust_fixtures["api_key"]) == rust_fixtures["api_key_hash"]


# ---- Python -> Rust ----------------------------------------------------------


def test_python_artifacts_verify_in_rust(
    rust_fixtures: dict, rust_verifier: str, config_with_secret
) -> None:
    secret = rust_fixtures["jwt_secret"]
    cfg = config_with_secret(secret)

    token, _exp = issue_token(cfg, rust_fixtures["user_id"], "py.user", [Role.OPERATOR, Role.ADMIN])
    argon2 = hash_password("a python-side password")

    key = bytes.fromhex(rust_fixtures["aes_key_from_secret_hex"])
    plaintext = "encrypted by Python, decrypted by Rust"
    record = Cipher(key).encrypt(plaintext.encode())

    req = {
        "jwt": token,
        "jwt_secret": secret,
        "argon2_hash": argon2,
        "password": "a python-side password",
        "aes_key_hex": key.hex(),
        "aes_record_hex": record.hex(),
        "aes_expect_plaintext": plaintext,
    }
    proc = subprocess.run(
        [rust_verifier, "verify"],
        input=json.dumps(req),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"rust verify failed:\n{proc.stderr}"
    assert "ALL OK" in proc.stderr
