from __future__ import annotations

import asyncio
import sys

import pytest

import squadrone.services.sandbox as sandbox_module
from squadrone.services.sandbox import (
    _communicate_poc_bounded,
    _kill_poc_process_group,
)


async def _python_process(source: str) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        source,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )


@pytest.mark.asyncio
async def test_poc_output_is_drained_concurrently_under_bounds() -> None:
    proc = await _python_process(
        "import sys; print('out'); print('err', file=sys.stderr)"
    )
    try:
        stdout, stderr = await _communicate_poc_bounded(proc)
    finally:
        await _kill_poc_process_group(proc)

    assert proc.returncode == 0
    assert stdout == b"out\n"
    assert stderr == b"err\n"


@pytest.mark.asyncio
async def test_poc_output_overflow_fails_without_retaining_the_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox_module, "_POC_OUTPUT_LIMIT_BYTES", 32)
    proc = await _python_process("import sys; sys.stdout.write('x' * 64)")
    try:
        with pytest.raises(RuntimeError, match="PoC stdout exceeded 32 bytes"):
            await _communicate_poc_bounded(proc)
    finally:
        await _kill_poc_process_group(proc)

    assert proc.returncode is not None
