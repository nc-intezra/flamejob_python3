"""Plaintext-at-rest encryption (AES-256-GCM). Port of ``crypto.rs``.

Record layout is ``nonce(12) || ciphertext || tag(16)`` — identical to the Rust
``aes-gcm`` crate output (ciphertext and the 16-byte GCM tag concatenated), so
records written by either server decrypt on the other against the same key.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import Config

_NONCE_LEN = 12


class Cipher:
    """AES-256-GCM cipher over a 32-byte key."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be exactly 32 bytes")
        self._key = key
        self._aes = AESGCM(key)

    @classmethod
    def from_bytes(cls, key: bytes) -> Cipher:
        return cls(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(_NONCE_LEN)
        # cryptography returns ciphertext||tag — same ordering as aes-gcm's
        # Aead::encrypt, so the full record matches the Rust layout.
        return nonce + self._aes.encrypt(nonce, plaintext, None)

    def decrypt(self, data: bytes) -> bytes | None:
        if len(data) < _NONCE_LEN:
            return None
        nonce, ct = data[:_NONCE_LEN], data[_NONCE_LEN:]
        try:
            return self._aes.decrypt(nonce, ct, None)
        except Exception:
            return None


def key_from_config(cfg: Config) -> bytes:
    """Load the 32-byte data key.

    Prefers the dedicated hex key file (the production / FJ-003-correct path);
    falls back to ``SHA-256(jwt_secret)`` for dev, exactly as the Rust server —
    kept only for interop during the strangler. The Phase-0/§6 hardening gives
    the Python server its own required key file and refuses the derived key
    outside dev.
    """
    path = cfg.crypto.plaintext_key_file
    if path:
        try:
            text = open(path, encoding="utf-8").read().strip()
            key = bytes.fromhex(text)
            if len(key) == 32:
                return key
        except (OSError, ValueError):
            pass
    return hashlib.sha256(cfg.auth.jwt_secret.encode()).digest()
