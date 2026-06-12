"""Unit tests for LLM transport retry classification."""

from __future__ import annotations

import ssl

from squadrone.services.llm import _is_retryable_llm_error


def test_ssl_bad_record_mac_is_retryable():
    exc = ssl.SSLError("[SSL: SSLV3_ALERT_BAD_RECORD_MAC] ssl/tls alert bad record mac")

    assert _is_retryable_llm_error(exc)


def test_schema_or_validation_error_is_not_retryable():
    exc = ValueError("Your JSON failed schema validation")

    assert not _is_retryable_llm_error(exc)
