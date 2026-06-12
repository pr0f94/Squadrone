"""Append-only per-run decision ledger.

The stage artifacts remain the source of truth. This ledger gives operators a
single compact timeline of keep/drop/manual/confirm decisions across stages.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

LEDGER_FILENAME = "decision_ledger.jsonl"


def ledger_path(run_dir: str | Path) -> Path:
    return Path(run_dir) / LEDGER_FILENAME


def append_decision(
    run_dir: str | Path,
    *,
    stage: str,
    action: str,
    result: str,
    hypothesis_id: str | None = None,
    finding_id: str | None = None,
    reason: str | None = None,
    artifact: str | Path | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Append a compact decision record to ``decision_ledger.jsonl``.

    Ledger writes are best-effort. They should never change scan behavior.
    """
    path = ledger_path(run_dir)
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "action": action,
        "result": result,
    }
    if hypothesis_id:
        record["hypothesis_id"] = hypothesis_id
    if finding_id:
        record["finding_id"] = finding_id
    if reason:
        record["reason"] = reason
    if artifact:
        record["artifact"] = str(artifact)
    if details:
        record["details"] = details

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except Exception as exc:
        logger.warning("decision ledger write failed for %s: %s", path, exc)
