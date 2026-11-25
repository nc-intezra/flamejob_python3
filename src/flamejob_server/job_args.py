"""hashcat argument validation (FJ-004 fix).

The Rust server appends ``JobConfig.extra_args`` to the hashcat command line
verbatim — a submitter can redirect ``--outfile``/``--potfile-path``/etc. to any
path writable by the runner (arbitrary file write). The port replaces that with
a strict server-side allowlist of safe tuning flags; anything else is rejected
before the job is created. Masks are validated against the hashcat mask charset.
"""

from __future__ import annotations

import re

from .errors import BadRequest

# Boolean tuning flags with no value.
_ALLOWED_BOOL = {
    "-O",
    "--optimized-kernel-enable",
    "-S",
    "--slow-candidates",
    "--force",
}
# Tuning flags that take a value (``--flag value`` or ``--flag=value``); the
# value must be a safe token (digits, letters, commas) — never a path.
_ALLOWED_VALUE = {
    "-w",
    "--workload-profile",
    "-D",
    "--opencl-device-types",
    "-d",
    "--backend-devices",
    "--spin-damp",
    "--kernel-accel",
    "--kernel-loops",
}
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9,]+$")
# hashcat mask charset: ?l?u?d?s?a?b?h?H + literals; keep it to printable,
# non-whitespace, no shell/path metacharacters.
_MASK_RE = re.compile(r"^[A-Za-z0-9?,.\-_:+=@%!#]+$")


def validate_extra_args(args: list[str]) -> list[str]:
    """Return the args unchanged if every one is an allowlisted tuning flag.

    Rejects any path-bearing or output/restore/potfile/debug flag and anything
    starting with ``-`` that is not on the allowlist.
    """
    out: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _ALLOWED_BOOL:
            out.append(arg)
            i += 1
            continue
        if "=" in arg:
            flag, _, value = arg.partition("=")
            if flag in _ALLOWED_VALUE and _SAFE_VALUE.match(value):
                out.append(arg)
                i += 1
                continue
            raise BadRequest(f"disallowed hashcat option: {arg!r}")
        if arg in _ALLOWED_VALUE:
            if i + 1 >= len(args) or not _SAFE_VALUE.match(args[i + 1]):
                raise BadRequest(f"option {arg!r} needs a safe value")
            out.append(arg)
            out.append(args[i + 1])
            i += 2
            continue
        raise BadRequest(f"disallowed hashcat option: {arg!r}")
    return out


def validate_mask(mask: str) -> str:
    if not mask or not _MASK_RE.match(mask):
        raise BadRequest("invalid mask")
    return mask
