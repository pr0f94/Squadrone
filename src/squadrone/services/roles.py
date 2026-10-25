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

# Recognition is not attribution: matches are used only inside explicit
# attacker clauses, never to pick the lowest role appearing anywhere in prose.
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


_ACTOR_CLAUSE = re.compile(
    r"\b(?:attacker|caller|requester|actor)(?:\s+role)?\s+"
    r"(?:is|are|must\s+be|can|has|holds|requires)\b|"
    r"\b(?:attacker|caller|requester|actor)(?:\s+role)?\s*[:=]|"
    r"\blowest\s+(?:attacker\s+)?role\s*[:=]",
    re.IGNORECASE,
)
_VICTIM_BOUNDARY = re.compile(
    r"\b(?:victim|target\s+user|viewed\s+by|previewed\s+by|"
    r"rendered\s+for|shown\s+to|visited\s+by|read\s+by)\b",
    re.IGNORECASE,
)
_ROLE_LEAD_SUFFIX = re.compile(
    r"^(?:$|\s*(?:[,;:/()]|attacker\b|caller\b|account\b|user\b|role\b|"
    r"with\b|without\b|who\b|that\b|or\b|and\b|can\b|must\b|on\b|remote\b|"
    r"payload\b|saving\b|editing\b|"
    r"creating\b|publishing\b|submits?\b|saves?\b))"
)
_NEGATED_ROLE_PREFIX = re.compile(
    r"\b(?:not|no|without|except|excluding|neither|nor|rather\s+than)\s+"
    r"(?:(?:an?|the|authenticated)\s+)*$"
)
_ROLE_PREREQUISITE_PREFIX = re.compile(r"\bas\s+(?:an?\s+)?$")
_ROLE_PREREQUISITE_SUFFIX = re.compile(
    r"\s+(?:account|role|user|with|permissions?|capabilit(?:y|ies))\b"
)
_UNPROVEN_ACTOR_PREFIX = re.compile(
    r"\b(?:not|no\s+(?:proof|evidence)|unknown|unclear|unproven|whether|if|unless)"
    r"\b.{0,40}$",
    re.IGNORECASE,
)


def extract_attacker_roles(value: str) -> frozenset[str]:
    """Extract positive, explicitly attributed roles from prerequisites.

    This is a conservative text consistency check, not a capability oracle.
    Victim, setup, negated and incidental role mentions prove no attacker role.
    Multiple explicit alternatives are retained instead of choosing the lowest.
    """
    roles: set[str] = set()
    for sentence in re.split(r"[.!?]\s+|;\s*|\n+", value):
        actor = _ACTOR_CLAUSE.search(sentence)
        if actor and _UNPROVEN_ACTOR_PREFIX.search(sentence[: actor.start()]):
            continue
        action_clause = bool(actor and re.search(r"\bcan\s*$", actor.group(), re.I))
        if actor:
            clause = sentence[actor.end() :]
        else:
            clause = re.sub(
                r"^(?:(?:an?|the|authenticated|logged[- ]in)\s+)+",
                "",
                sentence.strip(),
                flags=re.IGNORECASE,
            )
            words = _role_words(clause)
            # Canonical role followed by a parenthetical capability annotation
            # is still role-led. Keep scanning the annotation as well, so a
            # second positive role cannot be silently discarded.
            parenthetical_role = (
                _EXACT_ROLE_ALIASES.get(_role_words(clause.split("(", 1)[0]))
                if "(" in clause and ")" in clause
                else None
            )
            leading = [
                match
                for _, pattern in _DESCRIPTIVE_ROLE_PATTERNS
                if (match := pattern.match(words)) is not None
                and _ROLE_LEAD_SUFFIX.match(words[match.end() :]) is not None
            ]
            if not leading and parenthetical_role in {None, UNKNOWN_ATTACKER_ROLE}:
                continue
        clause = _VICTIM_BOUNDARY.split(clause, maxsplit=1)[0]
        words = _role_words(clause)
        for canonical, pattern in _DESCRIPTIVE_ROLE_PATTERNS:
            for match in pattern.finditer(words):
                prefix = words[: match.start()]
                if _NEGATED_ROLE_PREFIX.search(prefix):
                    continue
                # "can author content" uses a verb, and "can open the editor"
                # names a UI. Neither establishes an Author/Editor account.
                if action_clause and not (
                    _ROLE_PREREQUISITE_PREFIX.search(prefix)
                    or _ROLE_PREREQUISITE_SUFFIX.match(words[match.end() :])
                ):
                    continue
                roles.add(canonical)
    return frozenset(roles)


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
    roles = extract_attacker_roles(str(value or ""))
    if len(roles) == 1:
        return next(iter(roles))
    return UNKNOWN_ATTACKER_ROLE
