"""Unit tests for LLM transport retry classification."""

from __future__ import annotations

import ssl

from litellm.exceptions import APIError

from squadrone.services.llm import _is_retryable_llm_error


def test_ssl_bad_record_mac_is_retryable():
    exc = ssl.SSLError("[SSL: SSLV3_ALERT_BAD_RECORD_MAC] ssl/tls alert bad record mac")

    assert _is_retryable_llm_error(exc)


def test_schema_or_validation_error_is_not_retryable():
    exc = ValueError("Your JSON failed schema validation")

    assert not _is_retryable_llm_error(exc)


def _api_error(message: str) -> APIError:
    return APIError(
        status_code=503,
        message=message,
        llm_provider="test-provider",
        model="test-model",
    )


def test_temporal_model_access_error_with_retry_directive_is_retryable():
    exc = _api_error("Unable to verify model access right now. Please retry.")

    assert _is_retryable_llm_error(exc)


def test_permanent_access_error_with_remediation_is_not_retryable():
    exc = _api_error(
        "Access denied right now. Please retry with valid credentials."
    )

    assert not _is_retryable_llm_error(exc)
