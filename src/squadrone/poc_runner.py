"""Run a generated PoC with HTTP clients pointed at a parent-owned proxy.

This child-side module deliberately owns no trace salt, token, record sink, or
inherited file descriptor. The parent passes only a loopback proxy URL. The
proxy observes upstream traffic independently, so response hooks in a PoC
cannot rewrite the verifier's evidence.
"""

from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

from .poc_proxy import (  # noqa: F401 - compatibility re-exports
    ACTOR_RECEIPT_HEADER,
    POC_PROXY_ENV,
    PRIVATE_TRACE_ENV_NAMES,
    REQUEST_DIGEST_HEADER,
    REQUEST_NONCE_HEADER,
    RESPONSE_BODY_CAPTURE_LIMIT,
    TRACE_FD_ENV,
    TRACE_NONCE_HEADER,
    TRACE_ORIGIN_ENV,
    TRACE_SALT_ENV,
    TRACE_TOKEN_ENV,
    TRACE_TOKEN_HEADER,
    canonical_request_digest,
    configure_proxy_environment,
    normalize_trace_origin,
    normalize_trace_scalar,
    request_trace_fields,
    salted_scalar_sha256,
)


def _consume_proxy_environment() -> str:
    """Consume the sole supervisor control value and scrub obsolete secrets."""
    proxy_url = os.environ.pop(POC_PROXY_ENV, "")
    for name in PRIVATE_TRACE_ENV_NAMES:
        os.environ.pop(name, None)
    if not proxy_url:
        raise RuntimeError(f"missing PoC proxy environment: {POC_PROXY_ENV}")
    configure_proxy_environment(os.environ, proxy_url)
    return proxy_url


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        raise SystemExit("usage: python -m squadrone.poc_runner SCRIPT.py")
    script_path = Path(args[0]).resolve()
    if not script_path.is_file():
        raise SystemExit(f"PoC script does not exist: {script_path}")

    _consume_proxy_environment()
    sys.path.insert(0, str(script_path.parent))
    sys.argv = [str(script_path)]
    runpy.run_path(str(script_path), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
