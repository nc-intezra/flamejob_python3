"""flamejob-runner: hashcat execution (asyncio.subprocess, direct argv).

Phase 4. hashcat is spawned with ``asyncio.create_subprocess_exec(*argv)`` —
never ``shell=True`` — and ``extra_args`` passes through a server-validated
allowlist (FJ-004). See ``claude/flamejob-python-port-plan.md`` §4, §6.
"""
