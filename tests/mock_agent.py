"""Mock-agent test helpers (P2-05): CSR generation + frame builders.

Grows in later sub-phases into a full driver (answers ComputeKeyspace, accepts
Assign, streams Progress). Phase 2a needs the enroll CSR + the inbound frames.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def gen_csr(common_name: str = "flamejob-agent") -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate an EC P-256 key + a CSR PEM, as a real agent would at enrollment."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()
