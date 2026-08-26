"""Canonical attacker-role parsing shared by triage, verification, and dedup."""

from __future__ import annotations

import re


UNKNOWN_ATTACKER_ROLE = "unknown"

# These are the only canonical roles currently accepted by automatic disclosure
# routing. More privileged WordPress roles remain useful for scoring and dedup.
STANDARD_PROGRAM_ATTACKER_ROLES = frozenset(
    {"unauthenticated", "subscriber", "customer", "low_priv"}
)

_EXACT_ROLE_ALIASES = {
    "unauthenticated": "unauthenticated",
    "anonymous": "unauthenticated",
    "guest": "unauthenticated",
    "subscriber": "subscriber",
    "customer": "customer",
    "shop customer": "customer",
    "low priv": "low_priv",
    "low privilege": "low_priv",
    "low privileged": "low_priv",
    "contributor": "contributor",
    "author": "author",
    "editor": "editor",
    "shop manager": "shop_manager",
    "administrator": "administrator",
    "admin": "administrator",
    "manage options": "administrator",
    "unknown": UNKNOWN_ATTACKER_ROLE,
}

# Ordered from least to most privilege. If a description names both the attacker
# and a more privileged victim, retain the lowest explicit attacker capability,
# matching the pipeline's long-standing low-role-first inference behavior.
_DESCRIPTIVE_ROLE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "unauthenticated",
        re.compile(r"\b(?:unauthenticated|anonymous|guest)\b"),
    ),
    ("subscriber", re.compile(r"\bsubscriber\b")),
    ("customer", re.compile(r"\b(?:shop\s+customer|customer)\b")),
    (
        "low_priv",
        re.compile(r"\blow\s+priv(?:ilege|ileged)?\b"),
    ),
    ("contributor", re.compile(r"\bcontributor\b")),
    ("author", re.compile(r"\bauthor\b")),
    ("editor", re.compile(r"\beditor\b")),
    ("shop_manager", re.compile(r"\bshop\s+manager\b")),
    (
        "administrator",
        re.compile(
            r"\badministrator\b|\bmanage\s+options\b|"
            r"\badmin\s+(?:account|attacker|caller|role|user)\b|"
            r"\bas\s+(?:an?\s+)?admin\b"
        ),
    ),
)


def _role_words(value: object) -> str:
    """Normalize separators without assigning any role semantics."""
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").strip().lower()).strip()


def normalize_attacker_role(value: object) -> str:
    """Return one recognized canonical role, or ``unknown`` fail-closed.

    Model artifacts often contain a role plus short explanatory prose. This
    accepts such descriptions while refusing to invent a role from generic text
    such as ``authenticated user``.
    """
    words = _role_words(value)
    if not words:
        return UNKNOWN_ATTACKER_ROLE
    exact = _EXACT_ROLE_ALIASES.get(words)
    if exact is not None:
        return exact
    for canonical, pattern in _DESCRIPTIVE_ROLE_PATTERNS:
        if pattern.search(words):
            return canonical
    return UNKNOWN_ATTACKER_ROLE
