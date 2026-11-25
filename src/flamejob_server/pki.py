"""Agent PKI. Port of ``pki.rs``.

A self-signed CA persisted under ``{data_dir}/pki`` signs agent CSRs at
enrollment. The agent keeps its private key; the server returns the CA-signed
cert. Connection auth is a pure fingerprint match (``SHA-256`` of the issued
cert's **DER**, hex) against ``agents.fingerprint`` — the cert chain is not
validated (FJ-006), so pointing the Python server at the **same ``data_dir``**
as Rust reuses the existing CA and keeps already-enrolled agents working.

Hardening vs the Rust version: the CA key file is written ``0600`` (FJ-020) and
CSR signing is **constrained** — fixed validity, ``CA:false`` — regardless of
what the CSR requests (FJ-017).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import NameOID

_AGENT_CERT_DAYS = 825


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint_of_pem(cert_pem: str) -> str:
    """SHA-256 (hex) of the DER inside a certificate PEM."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return _sha256_hex(cert.public_bytes(serialization.Encoding.DER))


def _sig_hash(key: CertificateIssuerPrivateKeyTypes) -> hashes.SHA256 | None:
    # Ed25519 signs with no separate digest; EC/RSA use SHA-256.
    return None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()


class Pki:
    def __init__(
        self,
        ca_cert: x509.Certificate,
        ca_key: CertificateIssuerPrivateKeyTypes,
        ca_pem: str,
    ) -> None:
        self._ca_cert = ca_cert
        self._ca_key = ca_key
        self._ca_pem = ca_pem

    @property
    def ca_pem(self) -> str:
        return self._ca_pem

    @classmethod
    def load_or_create(cls, data_dir: str | Path) -> Pki:
        directory = Path(data_dir) / "pki"
        directory.mkdir(parents=True, exist_ok=True)
        cert_path = directory / "ca.pem"
        key_path = directory / "ca.key.pem"

        if cert_path.exists() and key_path.exists():
            ca_pem = cert_path.read_text(encoding="utf-8")
            ca_cert = x509.load_pem_x509_certificate(ca_pem.encode())
            ca_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            return cls(ca_cert, ca_key, ca_pem)  # type: ignore[arg-type]

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "flamejob agent CA")])
        now = dt.datetime.now(dt.timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        cert_path.write_text(ca_pem, encoding="utf-8")
        # FJ-020: restrictive mode on the CA private key, not the process umask.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key_pem)
        return cls(ca_cert, key, ca_pem)

    def sign_csr(self, csr_pem: str) -> tuple[str, str]:
        """Sign an agent CSR. Returns (cert_pem, fingerprint_hex).

        Issuance is constrained server-side (FJ-017): the CSR's public key and
        subject are used, but CA:false and a bounded validity are forced
        regardless of what the CSR requested.
        """
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise ValueError("csr signature invalid")
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=_AGENT_CERT_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._ca_key, _sig_hash(self._ca_key))
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        fingerprint = _sha256_hex(cert.public_bytes(serialization.Encoding.DER))
        return cert_pem, fingerprint
