"""FJ-004 allowlist unit tests."""

from __future__ import annotations

import pytest

from flamejob_server.errors import BadRequest
from flamejob_server.job_args import validate_extra_args, validate_mask


def test_allowed_tuning_flags_pass() -> None:
    args = ["-O", "-w", "3", "--opencl-device-types=1", "--kernel-accel=8"]
    assert validate_extra_args(args) == args


def test_split_value_flag() -> None:
    assert validate_extra_args(["-w", "3"]) == ["-w", "3"]


def test_rejects_output_redirect() -> None:
    with pytest.raises(BadRequest):
        validate_extra_args(["--outfile=/etc/cron.d/x"])
    with pytest.raises(BadRequest):
        validate_extra_args(["--potfile-path", "/tmp/p"])
    with pytest.raises(BadRequest):
        validate_extra_args(["--restore-file-path=/tmp/r"])


def test_rejects_unknown_and_path_values() -> None:
    with pytest.raises(BadRequest):
        validate_extra_args(["--totally-made-up"])
    with pytest.raises(BadRequest):
        validate_extra_args(["-w", "/etc/passwd"])  # value is a path, not a safe token


def test_mask_validation() -> None:
    assert validate_mask("?l?d?d") == "?l?d?d"
    with pytest.raises(BadRequest):
        validate_mask("../../etc/passwd")
    with pytest.raises(BadRequest):
        validate_mask("")
