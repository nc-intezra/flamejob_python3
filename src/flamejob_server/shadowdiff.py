"""Response-diff logic for the M1 read-shadow gate (P1-12).

Pure functions so they are unit-testable without live servers; the CLI
(``tools/diff_shadow.py``) wraps them with httpx to call the Rust and Python
servers and report per-endpoint diffs.
"""

from __future__ import annotations

import json
from typing import Any

# The M1 read set Python serves (templated paths get an id substituted by the CLI).
READ_ENDPOINTS: tuple[str, ...] = (
    "/auth/me",
    "/auth/api-keys",
    "/auth/capabilities",
    "/jobs",
    "/jobs/history",
    "/hashlists",
    "/files",
    "/files/usage",
    "/devices",
)

# Fields that legitimately differ between the two servers in M1 and must be
# normalised away before comparison (per-endpoint JSON paths, dotted; "[]" means
# "every list element").
VOLATILE: dict[str, tuple[str, ...]] = {
    # remote-mode live agent names come from the Rust hub (Phase 2 on the Python side)
    "/jobs": ("[].running_agents",),
    # disk free space drifts between the two sampling instants
    "/files/usage": ("disk_available_bytes",),
}


def _strip(obj: Any, dotted: str) -> None:
    head, _, rest = dotted.partition(".")
    if head == "[]":
        if isinstance(obj, list):
            for item in obj:
                _strip(item, rest)
        return
    if isinstance(obj, dict):
        if rest:
            if head in obj:
                _strip(obj[head], rest)
        else:
            obj.pop(head, None)


def normalize(path: str, obj: Any, drop: tuple[str, ...] = ()) -> Any:
    fields = VOLATILE.get(path, ()) + drop
    for f in fields:
        _strip(obj, f)
    return obj


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def compare(path: str, rust: Any, python: Any, drop: tuple[str, ...] = ()) -> list[str]:
    """Return a list of human-readable diffs (empty == identical after normalisation)."""
    r = normalize(path, rust, drop)
    p = normalize(path, python, drop)
    if canonical(r) == canonical(p):
        return []
    return _diff_detail(path, r, p)


def _diff_detail(prefix: str, a: Any, b: Any) -> list[str]:
    out: list[str] = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append(f"{prefix}.{k}: only in python")
            elif k not in b:
                out.append(f"{prefix}.{k}: only in rust")
            else:
                out.extend(_diff_detail(f"{prefix}.{k}", a[k], b[k]))
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{prefix}: length rust={len(a)} python={len(b)}")
        else:
            for i, (x, y) in enumerate(zip(a, b, strict=False)):
                out.extend(_diff_detail(f"{prefix}[{i}]", x, y))
    elif a != b:
        out.append(f"{prefix}: rust={a!r} python={b!r}")
    return out
