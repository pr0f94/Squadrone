#!/usr/bin/env python3
"""Probe chatgpt/gpt-5.5 with an in-process LiteLLM model-map patch.

This script does not modify Squadrone or LiteLLM on disk. It clones the installed
chatgpt/gpt-5.4 model metadata to chatgpt/gpt-5.5 for the current Python process
and sends a tiny request. If the backend returns HTML/Cloudflare, the issue is
server-side routing/entitlement rather than a local model registry gap.
"""

from __future__ import annotations

import asyncio
import copy
import json
import sys
import traceback

import litellm


SOURCE_MODEL = "chatgpt/gpt-5.4"
TARGET_MODEL = "chatgpt/gpt-5.5"


def patch_model_map() -> None:
    source = litellm.model_cost.get(SOURCE_MODEL)
    if not source:
        raise RuntimeError(f"LiteLLM model map does not contain {SOURCE_MODEL}")

    patched = copy.deepcopy(source)
    patched["litellm_provider"] = "chatgpt"
    patched["mode"] = "responses"
    litellm.model_cost[TARGET_MODEL] = patched

    # Some LiteLLM code paths use provider model sets for routing/wildcards.
    chatgpt_models = getattr(litellm, "chatgpt_models", None)
    if isinstance(chatgpt_models, set):
        chatgpt_models.add(TARGET_MODEL)
    elif isinstance(chatgpt_models, list) and TARGET_MODEL not in chatgpt_models:
        chatgpt_models.append(TARGET_MODEL)


def summarise_exception(exc: BaseException) -> str:
    pieces = [f"{type(exc).__name__}: {exc}"]
    response = getattr(exc, "response", None)
    if response is not None:
        pieces.append(f"status={getattr(response, 'status_code', 'unknown')}")
        headers = getattr(response, "headers", {}) or {}
        pieces.append(f"content-type={headers.get('content-type', 'unknown')}")
        text = getattr(response, "text", "") or ""
        if text:
            pieces.append("body_preview=" + text[:1000].replace("\n", "\\n"))
    return "\n".join(pieces)


async def main() -> int:
    patch_model_map()
    print(f"Patched LiteLLM model map: {TARGET_MODEL} cloned from {SOURCE_MODEL}")

    try:
        response = await litellm.acompletion(
            model=TARGET_MODEL,
            messages=[
                {
                    "role": "user",
                    "content": "Reply with exactly: squadrone-ok",
                }
            ],
            max_tokens=20,
            timeout=60,
        )
    except Exception as exc:
        print("REQUEST_FAILED")
        print(summarise_exception(exc))
        if "--traceback" in sys.argv:
            traceback.print_exc()
        return 1

    print("REQUEST_OK")
    try:
        print(json.dumps(response.model_dump(), indent=2, default=str)[:4000])
    except Exception:
        print(repr(response)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
