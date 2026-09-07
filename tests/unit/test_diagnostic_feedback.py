from __future__ import annotations

from squadrone.agents.poc_author import _format_previous_attempts
from squadrone.schemas.finding import PoCAttempt, PoCStatus
from squadrone.services.diagnostics import (
    DIAGNOSTIC_OMISSION_MARKER,
    bound_diagnostic,
)
from squadrone.services.sandbox import SandboxRunResult
from squadrone.stages.verify import (
    _attempt_error_log_snippet,
    _attempt_response_snippet,
)


def _failed_result(*, output: str = "", error_log: str = "") -> SandboxRunResult:
    return SandboxRunResult(
        success=False,
        output=output,
        elapsed=0.1,
        error_log=error_log,
        validation_reason="PoC process exited before validation completed",
    )


def test_long_failed_traceback_retains_final_exception_within_bound() -> None:
    traceback = "\n".join(
        [
            "Traceback (most recent call last):",
            *(f'  File "poc.py", line {line}, in generated_step' for line in range(80)),
            'SQUADRONE_RESULT={"private_oracle":"do-not-persist"}',
            "RuntimeError: rendered form bootstrap failed at the final request",
        ]
    )

    snippet = _attempt_error_log_snippet(_failed_result(error_log=traceback))

    assert snippet is not None
    assert len(snippet) == 500
    assert snippet.startswith("Traceback (most recent call last):")
    assert DIAGNOSTIC_OMISSION_MARKER in snippet
    assert snippet.endswith(
        "RuntimeError: rendered form bootstrap failed at the final request"
    )
    assert "do-not-persist" not in snippet
    assert "SQUADRONE_RESULT=" not in snippet


def test_long_failed_traceback_preserves_exception_before_late_logs() -> None:
    traceback = "\n".join(
        [
            "Traceback (most recent call last):",
            *(f'  File "poc.py", line {line}, in generated_step' for line in range(40)),
            "RuntimeError: actionable transport setup failure",
            *(f"late shutdown diagnostic {line}" for line in range(40)),
            "FINAL SHUTDOWN SENTINEL",
        ]
    )

    snippet = _attempt_error_log_snippet(_failed_result(error_log=traceback))

    assert snippet is not None
    assert len(snippet) == 500
    assert snippet.startswith("Traceback (most recent call last):")
    assert "RuntimeError: actionable transport setup failure" in snippet
    assert snippet.endswith("FINAL SHUTDOWN SENTINEL")
    assert snippet.count(DIAGNOSTIC_OMISSION_MARKER) == 2


def test_prioritized_exception_does_not_restore_rejected_result_line() -> None:
    traceback = "\n".join(
        [
            "Traceback (most recent call last):",
            *(f'  File "poc.py", line {line}, in generated_step' for line in range(40)),
            "RuntimeError: retained actionable failure",
            'SQUADRONE_RESULT={"private_oracle":"do-not-persist"}',
            *(f"late shutdown diagnostic {line}" for line in range(40)),
            "FINAL SHUTDOWN SENTINEL",
        ]
    )

    snippet = _attempt_error_log_snippet(_failed_result(error_log=traceback))

    assert snippet is not None
    assert len(snippet) == 500
    assert "RuntimeError: retained actionable failure" in snippet
    assert "do-not-persist" not in snippet
    assert "SQUADRONE_RESULT=" not in snippet


def test_prioritized_exception_respects_a_small_strict_bound() -> None:
    traceback = "\n".join(
        [
            "Traceback (most recent call last):",
            *(f'  File "poc.py", line {line}, in generated_step' for line in range(10)),
            "RuntimeError: retained even under a narrow diagnostic bound",
            *(f"late shutdown diagnostic {line}" for line in range(10)),
        ]
    )
    limit = (2 * len(DIAGNOSTIC_OMISSION_MARKER)) + 3

    snippet = bound_diagnostic(traceback, limit=limit)

    assert len(snippet) == limit
    assert snippet.count(DIAGNOSTIC_OMISSION_MARKER) == 2


def test_long_failed_response_retains_output_tail_within_bound() -> None:
    result = _failed_result(
        output="request setup began\n"
        + ("middle output\n" * 300)
        + "FINAL OUTPUT SENTINEL"
    )

    snippet = _attempt_response_snippet(result)

    assert snippet is not None
    assert len(snippet) == 500
    assert snippet.startswith("AUTHORITATIVE RUNNER VERDICT: FAILED")
    assert DIAGNOSTIC_OMISSION_MARKER in snippet
    assert snippet.endswith("FINAL OUTPUT SENTINEL")


def test_short_failed_error_log_is_unchanged() -> None:
    traceback = (
        "Traceback (most recent call last):\nRuntimeError: short actionable failure"
    )

    assert _attempt_error_log_snippet(_failed_result(error_log=traceback)) == traceback


def test_retry_context_retains_error_and_script_tails(tmp_path) -> None:
    script_path = tmp_path / "long_poc.py"
    script_path.write_text(
        "import requests\nCONFIG = 'retained head'\n"
        + ("# generated request preparation\n" * 220)
        + "raise RuntimeError('SCRIPT TAIL SENTINEL')\n",
        encoding="utf-8",
    )
    long_error = (
        "Traceback (most recent call last):\n"
        + ("  File 'long_poc.py', line 513, in <module>\n" * 20)
        + 'SQUADRONE_RESULT={"private_oracle":"do-not-prompt"}\n'
        + "RuntimeError: PROMPT ERROR TAIL SENTINEL"
    )
    attempt = PoCAttempt(
        iteration=1,
        script_path=str(script_path),
        result=PoCStatus.FAILED,
        error_log_snippet=long_error,
        validation_reason="PoC process exited before validation completed",
    )

    context = _format_previous_attempts([attempt])

    assert "import requests" in context
    assert "CONFIG = 'retained head'" in context
    assert "SCRIPT TAIL SENTINEL" in context
    assert "PROMPT ERROR TAIL SENTINEL" in context
    assert context.count(DIAGNOSTIC_OMISSION_MARKER) >= 2
    assert "do-not-prompt" not in context
    assert "SQUADRONE_RESULT=" not in context
