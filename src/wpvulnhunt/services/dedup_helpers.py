"""Stage-6 dedup helpers.

D1 — meaningful per-match similarity scoring (replaces uniform 1.0 with a real signal).
D4 — submission_recommendation derivation from scored matches + version-range alignment.
D5 — local review.md signal: re-flagged auto-finding for a sink we previously FP'd.

All static analysis — no LLM cost.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ..services.vuln_db import VulnMatch

logger = logging.getLogger(__name__)


# ---------- D1: per-match similarity scoring ------------------------------------------

# Vector hints we look for in CVE titles to distinguish XSS-via-Referer vs XSS-via-IP etc.
# Same plugin + same CWE-79 doesn't mean the same sink — these tags help discriminate.
_VECTOR_KEYWORDS = [
    "referer", "referrer", "ip", "user-agent", "user_agent", "useragent", "browser", "platform",
    "utm_source", "utm_", "?p=", "post_id", "user_id", "comment", "author", "header", "search",
    "filter", "sort", "order", "callback", "ajax", "rest", "shortcode", "preview",
]


def _tokens(text: str) -> set[str]:
    """Extract lowercase alphanumeric tokens from text for naive similarity."""
    return set(re.findall(r"[a-z0-9_]{3,}", (text or "").lower()))


def _affected_versions_score(match_versions: str | None, scanned_version: str) -> float:
    """Heuristic: 1.0 if scanned version is INSIDE the affected range; lower if past it.

    The match_versions string can be like:
      - "≤ 1.2.3"  → fixed at 1.2.4+
      - "<= 13.1.5"
      - "<13.2.2"
      - "1.0.0 - 1.5.0"
      - "Current"  → unknown
    """
    if not match_versions or not scanned_version:
        return 0.5  # unknown — neutral
    mv = match_versions.lower().strip().replace("≤", "<=").replace(" ", "")
    sv = _normalize_version(scanned_version)
    if "current" in mv or "all" in mv:
        return 0.5

    # Pattern: "<=X.Y.Z" or "<X.Y.Z"
    m = re.match(r"^([<≤]=?)([\d.]+)$", mv)
    if m:
        bound = _normalize_version(m.group(2))
        if _vt(sv) <= _vt(bound):
            return 1.0   # we're inside (or at) the affected range
        else:
            return 0.2   # we're after the fix — likely already patched
    # Pattern: "X.Y.Z-A.B.C"
    m = re.match(r"^([\d.]+)-([\d.]+)$", mv)
    if m:
        lo = _vt(_normalize_version(m.group(1)))
        hi = _vt(_normalize_version(m.group(2)))
        if lo <= _vt(sv) <= hi:
            return 1.0
        return 0.2
    return 0.5


def _normalize_version(v: str) -> str:
    """Strip non-version chars, keep only digits and dots."""
    return re.sub(r"[^\d.]", "", v or "")


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
    finding_tokens = _tokens(finding_sink) | _tokens(finding_handler) | _tokens(finding_file)
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


# ---------- D5: local review.md signal -----------------------------------------------

_FALSE_POSITIVES_HEADING = re.compile(r"^#{1,3}\s*False\s+Positives", re.IGNORECASE | re.MULTILINE)
_CONFIRMED_HEADING = re.compile(r"^#{1,3}\s*Confirmed\s+findings?", re.IGNORECASE | re.MULTILINE)
_NEXT_HEADING = re.compile(r"^#{1,3}\s+", re.MULTILINE)


def parse_review_md_signals(plugin_slug: str) -> dict:
    """Extract structured signals from plugins/<slug>/review.md.

    Returns:
        {
            "false_positives_text": str | "",
            "confirmed_text": str | "",
            "fp_keywords": set[str],
            "confirmed_keywords": set[str],
        }
    Empty dict if review.md not present.
    """
    p = Path("plugins") / plugin_slug / "review.md"
    if not p.exists():
        return {}
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return {}

    out: dict[str, Any] = {
        "false_positives_text": "",
        "confirmed_text": "",
        "fp_keywords": set(),
        "confirmed_keywords": set(),
    }

    def _section_after(pattern: re.Pattern[str], src: str) -> str:
        m = pattern.search(src)
        if not m:
            return ""
        start = m.end()
        # Find next H1/H2/H3 after start
        following = list(_NEXT_HEADING.finditer(src, pos=start))
        end = following[0].start() if following else len(src)
        return src[start:end].strip()

    fp_text = _section_after(_FALSE_POSITIVES_HEADING, text)
    conf_text = _section_after(_CONFIRMED_HEADING, text)
    out["false_positives_text"] = fp_text
    out["confirmed_text"] = conf_text
    out["fp_keywords"] = _tokens(fp_text)
    out["confirmed_keywords"] = _tokens(conf_text)
    return out


_REVIEW_MD_STOPWORDS = {
    "the", "and", "for", "wpdb", "wordpress", "plugin", "user", "post", "data", "via",
    "with", "this", "that", "from", "have", "been", "are", "any", "all", "but", "not",
    "set", "get", "use", "see", "via", "out", "off", "yes", "let", "had", "has",
    "single", "double", "first", "last", "real", "auto", "yet", "now", "old", "new",
    "case", "type", "name", "find", "look", "make", "left", "found", "finding",
    "confirmed", "bountyable", "manually", "disproven", "rejected", "accepted",
    "review", "html", "tag", "attribute", "text", "form", "value", "field",
    "function", "method", "class", "file", "line", "code", "test", "false",
    "true", "none", "null", "list", "string", "int", "bool",
}


def local_review_signal_for_finding(
    review_signals: dict,
    finding_sink: str,
    finding_file: str,
    finding_handler: str,
    min_overlap: int = 2,
) -> str | None:
    """Return a string signal if the finding's sink/file/handler matches a section of
    plugins/<slug>/review.md.

    Returns one of:
    - "previously_marked_fp"      — finding's sink appears in the False Positives section
    - "previously_confirmed"      — finding's sink appears in the Confirmed section
    - None                        — no overlap or no review.md

    Filters generic English/code-vocabulary stopwords and requires ≥`min_overlap`
    distinguishing tokens to fire — single-token coincidences (e.g. "single" because
    of "single-quoted attribute") are not enough.
    """
    if not review_signals:
        return None
    finding_keys = _tokens(finding_sink) | _tokens(finding_file) | _tokens(finding_handler)
    finding_keys -= _REVIEW_MD_STOPWORDS
    if not finding_keys:
        return None
    fp_overlap = (finding_keys & review_signals.get("fp_keywords", set())) - _REVIEW_MD_STOPWORDS
    conf_overlap = (finding_keys & review_signals.get("confirmed_keywords", set())) - _REVIEW_MD_STOPWORDS
    if len(conf_overlap) >= min_overlap and len(fp_overlap) < len(conf_overlap):
        return "previously_confirmed"
    if len(fp_overlap) >= min_overlap and len(conf_overlap) < len(fp_overlap):
        return "previously_marked_fp"
    return None


# ---------- D4: submission_recommendation --------------------------------------------

def derive_submission_recommendation(
    finding_dedup_status: str,
    scored_matches: list[dict],
    review_signal: str | None,
) -> tuple[str, str]:
    """Return (recommendation, reason).

    Recommendation values:
    - "skip_exact_dupe_of_<id>"      — top score >= 0.95, version range matches
    - "submit_as_regression_of_<id>" — top score >= 0.85 but our version is past affected range
    - "submit_with_dedup_rebuttal"   — top score in [0.5, 0.85] (similar but distinguishable)
    - "submit_as_novel"              — top score < 0.5 (no strong overlap)
    - "local_review_says_fp"         — D5 signal trumps: previously marked FP for this sink
    """
    if review_signal == "previously_marked_fp":
        return ("local_review_says_fp",
                "Sink/file/handler keywords overlap with the False Positives section of "
                "plugins/<slug>/review.md. We previously concluded this is not exploitable.")

    if not scored_matches:
        return ("submit_as_novel", "No matches in the vulnerability databases for this plugin+CWE.")

    # scored_matches is sorted high→low
    top = scored_matches[0]
    score = top.get("similarity_score", 0.0)
    cve_id = top.get("cve_id") or top.get("title", "(untitled)")[:40]
    affected = (top.get("affected_versions") or "").lower()

    if score >= 0.95:
        return (f"skip_exact_dupe_of_{cve_id}",
                f"Top match scores {score:.2f} — sink/handler/version all align with {cve_id}. "
                f"Likely already in the database.")
    if score >= 0.85 and ("≤" in affected or "<=" in affected or "<" in affected):
        return (f"submit_as_regression_of_{cve_id}",
                f"Top match {cve_id} scores {score:.2f} on the same sink class. "
                f"Affected versions string '{affected}' suggests it was patched; "
                f"if our version is past that, this is a regression.")
    if score >= 0.5:
        return ("submit_with_dedup_rebuttal",
                f"Top match {cve_id} scores {score:.2f} — similar bug class on same plugin. "
                f"Submission should include a dedup rebuttal explaining the distinguishing detail.")
    return ("submit_as_novel",
            f"Top match scores only {score:.2f} — no strong overlap with prior CVEs. "
            f"Submit as a novel finding.")
