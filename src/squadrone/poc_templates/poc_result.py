"""Structured observation emitter for generated proof-of-concept scripts."""

from __future__ import annotations

import json
from typing import Any


def emit_result(
    *,
    verdict: str,
    oracle: str,
    attacker_role: str,
    request: dict[str, Any],
    attack: dict[str, Any],
    control: dict[str, Any],
    confidentiality: str = "none",
    integrity: str = "none",
    availability: str = "none",
    impact: str,
) -> None:
    payload = {
        "schema_version": 1,
        "verdict": verdict,
        "oracle": oracle,
        "attacker_role": attacker_role,
        "request": request,
        "attack": attack,
        "control": control,
        "impact": {
            "confidentiality": confidentiality,
            "integrity": integrity,
            "availability": availability,
            "description": impact,
        },
    }
    print("SQUADRONE_RESULT=" + json.dumps(payload, sort_keys=True, default=str))
