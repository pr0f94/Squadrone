"""Trusted bindings for verification resume artifacts.

Verification outputs are safe to resume only when they were produced for the
complete, current accepted hypothesis under the current verifier policy.  IDs
are labels rather than content identities, so every checkpoint carries this
runner-owned digest as well as an explicit policy version.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from ..schemas.finding import Finding
from ..schemas.hypothesis import Hypothesis


# Increment whenever verifier semantics change in a way that can invalidate a
# prior confirmation or terminal negative.  Version 2 introduces the bounded,
# parent-attested CWE-78/CWE-94 execution oracle and complete hypothesis binding.
VERIFICATION_POLICY_VERSION = 2
VERIFICATION_CHECKPOINT_SCHEMA_VERSION = 2

_HYPOTHESIS_DIGEST_DOMAIN = b"squadrone:accepted-hypothesis:v1\x00"


def canonical_hypothesis_digest(hypothesis: Hypothesis) -> str:
    """Return a stable digest of every persisted accepted-hypothesis field."""
    payload = json.dumps(
        hypothesis.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(_HYPOTHESIS_DIGEST_DOMAIN + payload).hexdigest()


def verification_binding(hypothesis: Hypothesis) -> dict[str, Any]:
    """Build the runner-owned binding embedded in per-candidate artifacts."""
    return {
        "verification_policy_version": VERIFICATION_POLICY_VERSION,
        "hypothesis_id": hypothesis.id,
        "hypothesis_digest": canonical_hypothesis_digest(hypothesis),
    }


def verification_binding_matches(
    payload: Mapping[str, Any],
    hypothesis: Hypothesis,
) -> bool:
    """Fail closed unless a checkpoint exactly binds the current hypothesis."""
    expected = verification_binding(hypothesis)
    return all(payload.get(key) == value for key, value in expected.items())


def finding_verification_binding_matches(
    finding: Finding,
    hypothesis: Hypothesis,
) -> bool:
    """Correlate a finding to the exact accepted input and current policy.

    Verification replaces ``security_outcome`` with the reproduced outcome in
    the finding.  Every other embedded hypothesis field must still match the
    accepted candidate; the separately stored digest binds the original,
    complete accepted payload including its pre-verification outcome.
    """
    expected_digest = canonical_hypothesis_digest(hypothesis)
    accepted_view = finding.hypothesis.model_copy(
        update={"security_outcome": hypothesis.security_outcome},
        deep=True,
    )
    return (
        finding.verification_policy_version == VERIFICATION_POLICY_VERSION
        and finding.hypothesis_digest == expected_digest
        and canonical_hypothesis_digest(accepted_view) == expected_digest
    )
