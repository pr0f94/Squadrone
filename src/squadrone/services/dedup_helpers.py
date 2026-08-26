"""Static dedup similarity and submission-recommendation helpers."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import re

from ..services.roles import UNKNOWN_ATTACKER_ROLE, normalize_attacker_role
from ..services.vuln_db import VulnMatch

logger = logging.getLogger(__name__)


# ---------- Per-match similarity scoring ---------------------------------------------

# Vector hints we look for in CVE titles to distinguish XSS-via-Referer vs XSS-via-IP etc.
# Same plugin + same CWE-79 doesn't mean the same sink — these tags help discriminate.
_VECTOR_KEYWORDS = [
    "referer",
    "referrer",
    "ip",
    "user-agent",
    "user_agent",
    "useragent",
    "browser",
    "platform",
    "utm_source",
    "utm_",
    "?p=",
    "post_id",
    "user_id",
    "comment",
    "author",
    "header",
    "search",
    "filter",
    "sort",
    "order",
    "callback",
    "ajax",
    "rest",
    "shortcode",
    "preview",
]

_VERSION_PATTERN = r"\d+(?:\.\d+)*"
_TITLE_ROLE_RE = re.compile(
    r"\(\s*(subscriber|contributor|author|editor|administrator|admin|customer|"
    r"shop[\s_-]+manager)\s*\+\s*\)",
    re.IGNORECASE,
)
_VULNERABILITY_TITLE_PATTERNS = {
    "arbitrary_file_upload_or_write": (
        re.compile(r"\barbitrary\s+file\s+upload\b", re.IGNORECASE),
        re.compile(r"\barbitrary\s+file\s+write\b", re.IGNORECASE),
    ),
}


@dataclass(frozen=True)
class AffectedVersionMatch:
    """Strict relationship between a scan version and an affected-version expression."""

    in_range: bool | None
    exact_inclusive_bound: bool = False


def _tokens(text: str) -> set[str]:
    """Extract lowercase alphanumeric tokens from text for naive similarity."""
    return set(re.findall(r"[a-z0-9_]{3,}", (text or "").lower()))


def affected_version_match(
    match_versions: str | None,
    scanned_version: str,
) -> AffectedVersionMatch:
    """Parse Wordfence/WPScan ranges without treating unknown syntax as a match.

    Commas join constraints within one range and semicolons join alternative ranges.
    ``exact_inclusive_bound`` is deliberately narrower than membership: it is true only
    when the scanned version is literally an inclusive endpoint in a matching range.
    """
    if not match_versions or not scanned_version:
        return AffectedVersionMatch(None)

    scanned = _strict_version_tuple(scanned_version)
    if scanned is None:
        return AffectedVersionMatch(None)

    expression = (
        match_versions.strip()
        .replace("≤", "<=")
        .replace("≥", ">=")
        .replace("–", "-")
        .replace("—", "-")
    )
    if not expression or re.search(r"\b(?:all|current|unknown)\b|\*", expression, re.I):
        return AffectedVersionMatch(None)

    segment_results: list[tuple[bool, bool]] = []
    for raw_segment in expression.split(";"):
        segment = raw_segment.strip()
        if not segment:
            return AffectedVersionMatch(None)

        range_match = re.fullmatch(
            rf"({_VERSION_PATTERN})\s*-\s*({_VERSION_PATTERN})",
            segment,
        )
        if range_match:
            lower = _strict_version_tuple(range_match.group(1))
            upper = _strict_version_tuple(range_match.group(2))
            if lower is None or upper is None or lower > upper:
                return AffectedVersionMatch(None)
            inside = lower <= scanned <= upper
            segment_results.append((inside, inside and scanned in {lower, upper}))
            continue

        term_results: list[bool] = []
        exact_inclusive_bound = False
        for raw_term in segment.split(","):
            term = raw_term.strip()
            term_match = re.fullmatch(
                rf"(<=|>=|<|>|=)?\s*({_VERSION_PATTERN})",
                term,
            )
            if not term_match:
                return AffectedVersionMatch(None)
            operator = term_match.group(1) or "="
            bound = _strict_version_tuple(term_match.group(2))
            if bound is None:
                return AffectedVersionMatch(None)
            comparisons = {
                "<": scanned < bound,
                "<=": scanned <= bound,
                ">": scanned > bound,
                ">=": scanned >= bound,
                "=": scanned == bound,
            }
            term_results.append(comparisons[operator])
            if operator in {"<=", ">=", "="} and scanned == bound:
                exact_inclusive_bound = True

        inside = bool(term_results) and all(term_results)
        segment_results.append((inside, inside and exact_inclusive_bound))

    matching_segments = [result for result in segment_results if result[0]]
    if matching_segments:
        return AffectedVersionMatch(
            True,
            exact_inclusive_bound=any(result[1] for result in matching_segments),
        )
    return AffectedVersionMatch(False)


def _affected_versions_score(match_versions: str | None, scanned_version: str) -> float:
    """Heuristic: 1.0 if scanned version is INSIDE the affected range; lower if past it.

    The match_versions string can be like:
      - "≤ 1.2.3"  → fixed at 1.2.4+
      - "<= 13.1.5"
      - "<13.2.2"
      - "1.0.0 - 1.5.0"
      - "Current"  → unknown
    """
    relation = affected_version_match(match_versions, scanned_version)
    if relation.in_range is True:
        return 1.0
    if relation.in_range is False:
        return 0.2
    return 0.5


def _normalize_version(v: str) -> str:
    """Strip non-version chars, keep only digits and dots."""
    return re.sub(r"[^\d.]", "", v or "")


def _strict_version_tuple(v: str) -> tuple[int, ...] | None:
    match = re.fullmatch(rf"v?({_VERSION_PATTERN})", (v or "").strip(), re.IGNORECASE)
    if not match:
        return None
    return _vt(match.group(1))


def _vt(v: str) -> tuple[int, ...]:
    """Version tuple, padded to 4 components for comparison."""
    parts = (v or "0").split(".")
    out = []
    for p in parts[:4]:
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    while len(out) < 4:
        out.append(0)
    return tuple(out)


def _normalize_role(role: str) -> str:
    normalized = normalize_attacker_role(role)
    return "" if normalized == UNKNOWN_ATTACKER_ROLE else normalized


def _title_attacker_role(title: str) -> str | None:
    if re.search(r"\bunauthenticated\b", title or "", re.IGNORECASE):
        return "unauthenticated"
    match = _TITLE_ROLE_RE.search(title or "")
    if not match:
        return None
    return _normalize_role(match.group(1))


def is_exact_semantic_match(
    match: VulnMatch,
    finding_bug_class: str,
    scanned_version: str,
    finding_attacker_role: str,
    finding_vulnerability_type: str,
) -> bool:
    """Return true only for an explicit version/role/type match.

    Unsupported or missing title taxonomy is intentionally not inferred. The caller must
    still ensure this fingerprint identifies exactly one vulnerability record.
    """
    if (match.bug_class or "") != finding_bug_class:
        return False

    version = affected_version_match(match.affected_versions, scanned_version)
    if version.in_range is not True or not version.exact_inclusive_bound:
        return False

    finding_role = _normalize_role(finding_attacker_role)
    title_role = _title_attacker_role(match.title)
    if not finding_role or not title_role or finding_role != title_role:
        return False

    patterns = _VULNERABILITY_TITLE_PATTERNS.get(finding_vulnerability_type)
    if not patterns:
        return False
    return any(pattern.search(match.title or "") for pattern in patterns)


def score_match(
    match: VulnMatch,
    finding_bug_class: str,
    finding_sink: str,
    finding_handler: str,
    finding_file: str,
    scanned_version: str,
) -> float:
    """Return per-match similarity score in [0, 1].

    Components (additive, capped at 1.0):
    - 0.30 base for bug_class match (already pre-filtered)
    - 0.20 vector-keyword overlap between match.title and (sink, handler, file)
    - 0.20 affected-version-range alignment
    - 0.30 strong-signal boosts: title contains the literal sink string OR handler name
    """
    if (match.bug_class or "") != finding_bug_class:
        return 0.0

    score = 0.30

    title_tokens = _tokens(match.title)
    finding_tokens = (
        _tokens(finding_sink) | _tokens(finding_handler) | _tokens(finding_file)
    )
    overlap = title_tokens & finding_tokens & set(_VECTOR_KEYWORDS)
    if overlap:
        score += min(0.20, 0.05 * len(overlap))

    score += 0.20 * _affected_versions_score(match.affected_versions, scanned_version)

    # Strong signal: title quotes the sink or handler verbatim
    title_lc = (match.title or "").lower()
    if finding_sink and finding_sink.lower() in title_lc:
        score += 0.30
    elif finding_handler and finding_handler.lower() in title_lc:
        score += 0.20

    return min(1.0, round(score, 3))


# ---------- Submission recommendation ------------------------------------------------


def derive_submission_recommendation(
    finding_dedup_status: str,
    scored_matches: list[dict],
) -> tuple[str, str]:
    """Return (recommendation, reason).

    Recommendation values:
    - "skip_exact_dupe_of_<id>"      — top score >= 0.95, version range matches
    - "submit_as_regression_of_<id>" — top score >= 0.85 but our version is past affected range
    - "submit_with_dedup_rebuttal"   — top score in [0.5, 0.85] (similar but distinguishable)
    - "submit_as_novel"              — top score < 0.5 (no strong overlap)
    """
    if not scored_matches:
        return (
            "submit_as_novel",
            "No matches in the vulnerability databases for this plugin+CWE.",
        )

    # scored_matches is sorted high→low
    top = scored_matches[0]
    score = top.get("similarity_score", 0.0)
    cve_id = top.get("cve_id") or top.get("title", "(untitled)")[:40]
    affected = (top.get("affected_versions") or "").lower()

    if score >= 0.95:
        if top.get("exact_semantic_match"):
            return (
                f"skip_exact_dupe_of_{cve_id}",
                f"Affected version, attacker role, and vulnerability type uniquely align "
                f"with {cve_id}.",
            )
        return (
            f"skip_exact_dupe_of_{cve_id}",
            f"Top match scores {score:.2f} — sink/handler/version all align with {cve_id}. "
            f"Likely already in the database.",
        )
    if score >= 0.85 and ("≤" in affected or "<=" in affected or "<" in affected):
        return (
            f"submit_as_regression_of_{cve_id}",
            f"Top match {cve_id} scores {score:.2f} on the same sink class. "
            f"Affected versions string '{affected}' suggests it was patched; "
            f"if our version is past that, this is a regression.",
        )
    if score >= 0.5:
        return (
            "submit_with_dedup_rebuttal",
            f"Top match {cve_id} scores {score:.2f} — similar bug class on same plugin. "
            f"Submission should include a dedup rebuttal explaining the distinguishing detail.",
        )
    return (
        "submit_as_novel",
        f"Top match scores only {score:.2f} — no strong overlap with prior CVEs. "
        f"Submit as a novel finding.",
    )
