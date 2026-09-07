"""Machine-readable proof observations emitted by sandbox PoCs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel


ImpactLevel = Literal["none", "low", "high"]
OracleType = Literal[
    "authorization",
    "browser_execution",
    "callback",
    "cross_object_access",
    "file_effect",
    "object_instantiation",
    "response_marker",
    "state_change",
    "timing",
]


class CIAImpact(BaseModel):
    confidentiality: ImpactLevel = "none"
    integrity: ImpactLevel = "none"
    availability: ImpactLevel = "none"
    description: str = ""


class PoCObservation(BaseModel):
    """Measurements reported by a PoC for independent validation."""

    schema_version: Literal[1] = 1
    verdict: Literal["vulnerable", "not_vulnerable"]
    oracle: OracleType
    attacker_role: str
    request: dict[str, Any]
    attack: dict[str, Any]
    control: dict[str, Any]
    impact: CIAImpact
