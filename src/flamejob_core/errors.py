"""Domain errors. Port of ``crates/flamejob-core/src/error.rs``."""

from __future__ import annotations


class FlamejobError(Exception):
    """Base domain error."""


class InvalidTransition(FlamejobError):
    def __init__(self, frm: str, to: str) -> None:
        super().__init__(f"invalid state transition: {frm} -> {to}")
        self.frm = frm
        self.to = to


class RunnerError(FlamejobError):
    pass
