"""Canonical vulnerability taxonomy and declared Squadrone support."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from types import MappingProxyType
from typing import Literal, Mapping, cast


WordfencePolicy = Literal[
    "none",
    "direct",
    "qualifying_authorization",
    "usable_gadget",
]
PatchstackPolicy = Literal[
    "none",
    "direct",
    "concrete_ssrf",
    "qualifying_csrf",
    "significant_object",
    "sitewide_stored_xss",
]
CriticAcceptanceMode = Literal["source_review", "manual_review_only"]
CriticEvidenceJSONType = Literal["boolean", "string", "number"]

WORDFENCE_POLICIES = frozenset(
    {"none", "direct", "qualifying_authorization", "usable_gadget"}
)
PATCHSTACK_POLICIES = frozenset(
    {
        "none",
        "direct",
        "concrete_ssrf",
        "qualifying_csrf",
        "significant_object",
        "sitewide_stored_xss",
    }
)

# Canonical CWEs outside the reviewed registry retain their exact identifier and
# receive one conservative authoring fallback for manual review. They deliberately
# do not inherit an automatic oracle or disclosure policy.
OPEN_CWE_POC_TEMPLATE = "generic_open_cwe.py.j2"


@dataclass(frozen=True)
class CriticEvidenceRequirement:
    """One exact structured fact that a critic must establish from source."""

    path: str
    json_type: CriticEvidenceJSONType
    required_value: bool | str | int | float
    source_requirement: str


@dataclass(frozen=True)
class CriticEvidenceContract:
    """Family/profile-owned acceptance rules supplied to the source critic."""

    acceptance_mode: CriticAcceptanceMode
    acceptance_requirements: tuple[str, ...] = ()
    required_evidence: tuple[CriticEvidenceRequirement, ...] = ()
    non_evidence: tuple[str, ...] = ()


# Existing reviewed families retain the shared source-review behavior unless
# their taxonomy profile declares additional, independently reviewed evidence.
BASE_CRITIC_EVIDENCE_CONTRACT = CriticEvidenceContract(
    acceptance_mode="source_review"
)

# An open CWE has no reviewed family semantics or automatic oracle. The critic
# may still reject a disproven claim, but it must not silently accept one under
# assumptions borrowed from a superficially similar known family.
OPEN_CWE_CRITIC_EVIDENCE_CONTRACT = CriticEvidenceContract(
    acceptance_mode="manual_review_only",
    acceptance_requirements=(
        "No reviewed family-specific evidence contract exists for this canonical "
        "open CWE. Apply the shared source-validity checks, but route a surviving "
        "candidate to manual_review instead of accepted.",
    ),
)

_PHP_OBJECT_INJECTION_CRITIC_EVIDENCE_CONTRACT = CriticEvidenceContract(
    acceptance_mode="source_review",
    acceptance_requirements=(
        "Independently review a shipped-source gadget chain: its class is loaded "
        "or autoloadable, the required serialized property names and visibility "
        "encoding survive every proven ingress transform with exact byte lengths, "
        "and its magic method reaches the claimed concrete side effect.",
        "An optional automated natural-gadget proof recipe is valid only for one "
        "shipped object whose __wakeup or __destruct chain has complete exact "
        "class, trigger, helper, and unlink source anchors. It must declare one "
        "parent-supplied ephemeral file path, account for every unlink, and contain "
        "no raw serialization, path, nested object, reference, callback, dynamic "
        "helper, or other terminal side effect. Full direct-path promotion also "
        "requires immutable source-bound property/iteration dataflow with no "
        "aliases or by-reference helpers and no additional unreviewed magic hooks; "
        "a local-path helper must "
        "prove scheme rejection and same-argument local file existence, while a "
        "prefix-only deletion remains lower-tier evidence.",
    ),
    required_evidence=(
        CriticEvidenceRequirement(
            path="evidence_summary.usable_gadget",
            json_type="boolean",
            required_value=True,
            source_requirement=(
                "The independently reviewed shipped-source chain establishes a "
                "reachable usable gadget and concrete side effect."
            ),
        ),
    ),
    non_evidence=(
        "Verifier-owned canaries do not establish a usable shipped gadget.",
        "The mere occurrence of words such as 'gadget' or 'code execution' is not "
        "affirmative gadget evidence.",
        "Model-authored serialized bytes, filesystem paths, callback names, and "
        "unreviewed helper calls are not safe natural-gadget recipes.",
    ),
)


class BugClass(str, Enum):
    MISSING_CAP_CHECK = "CWE-862"
    MISSING_NONCE = "CWE-352"
    SQLI = "CWE-89"
    COMMAND_INJECTION = "CWE-78"
    PATH_TRAVERSAL = "CWE-22"
    ARBITRARY_FILE_WRITE = "CWE-434"
    SSRF = "CWE-918"
    XXE = "CWE-611"
    PHP_OBJECT_INJECTION = "CWE-502"
    XSS_REFLECTED = "CWE-79:reflected"
    XSS_STORED = "CWE-79:stored"
    OPEN_REDIRECT = "CWE-601"
    IDOR = "CWE-639"
    WEAK_CRYPTO = "CWE-327"
    WEAK_PRNG = "CWE-338"
    MASS_ASSIGNMENT = "CWE-915"
    AUTH_BYPASS = "CWE-287"
    MISSING_AUTH_CRITICAL_FUNCTION = "CWE-306"
    WEAK_PASSWORD_RECOVERY = "CWE-640"
    SESSION_FIXATION = "CWE-384"
    MISSING_RATE_LIMIT = "CWE-307"
    RESOURCE_EXHAUSTION = "CWE-400"
    LOGIC_FLAW = "CWE-840"

    @classmethod
    def _missing_(cls, value: object) -> BugClass | None:
        """Accept canonical future CWE ids without declaring support for them."""
        if (
            not isinstance(value, str)
            or re.fullmatch(r"CWE-[1-9][0-9]*", value) is None
        ):
            return None
        member = str.__new__(cls, value)
        member._name_ = f"UNMAPPED_CWE_{value.removeprefix('CWE-')}"
        member._value_ = value
        return member

    @property
    def is_known(self) -> bool:
        """Whether this value has an explicit, reviewed Squadrone profile."""
        return self.name in type(self).__members__

    @property
    def oracle_key(self) -> str:
        """Use stable enum names for known classes and exact CWE ids otherwise."""
        return self.name if self.is_known else self.value


@dataclass(frozen=True)
class KnownCWEProfile:
    """One explicit cross-layer contract for every declared bug class."""

    root_cwe: str
    family: str
    vulnerability_type: str
    reviewer: str | None
    deterministic_surfaces: tuple[str, ...]
    owasp_2021: str
    poc_template: str | None
    template_fit: str
    allowed_oracles: frozenset[str]
    wordfence_policy: WordfencePolicy
    patchstack_policy: PatchstackPolicy
    analysis_support: str
    delivery_support: str
    critic_evidence_contract: CriticEvidenceContract
    exclusion_reason: str = ""
    alternative_discovery: str = ""


def _profile(
    root_cwe: str,
    family: str,
    vulnerability_type: str,
    reviewer: str | None,
    *,
    surfaces: tuple[str, ...] = (),
    owasp: str,
    template: str | None,
    template_fit: str = "exact",
    oracles: tuple[str, ...] = (),
    wordfence: str = "none",
    patchstack: str = "none",
    analysis: str = "active",
    delivery: str = "automated",
    critic_evidence_contract: CriticEvidenceContract = BASE_CRITIC_EVIDENCE_CONTRACT,
    exclusion_reason: str = "",
    alternative_discovery: str = "",
) -> KnownCWEProfile:
    if wordfence not in WORDFENCE_POLICIES:
        raise ValueError(f"unknown Wordfence policy: {wordfence}")
    if patchstack not in PATCHSTACK_POLICIES:
        raise ValueError(f"unknown Patchstack policy: {patchstack}")
    return KnownCWEProfile(
        root_cwe=root_cwe,
        family=family,
        vulnerability_type=vulnerability_type,
        reviewer=reviewer,
        deterministic_surfaces=surfaces,
        owasp_2021=owasp,
        poc_template=template,
        template_fit=template_fit,
        allowed_oracles=frozenset(oracles),
        wordfence_policy=cast(WordfencePolicy, wordfence),
        patchstack_policy=cast(PatchstackPolicy, patchstack),
        analysis_support=analysis,
        delivery_support=delivery,
        critic_evidence_contract=critic_evidence_contract,
        exclusion_reason=exclusion_reason,
        alternative_discovery=alternative_discovery,
    )


_KNOWN_CWE_REGISTRY: dict[BugClass, KnownCWEProfile] = {
    BugClass.MISSING_CAP_CHECK: _profile(
        "CWE-862",
        "authorization_workflow",
        "missing_authorization",
        "authorization_workflows",
        surfaces=("entry_point", "role_capability_write"),
        owasp="A01:2021-Broken Access Control",
        template="auth_bypass.py.j2",
        oracles=(
            "authorization",
            "cross_object_access",
            "file_effect",
            "response_marker",
            "state_change",
        ),
        wordfence="qualifying_authorization",
        patchstack="direct",
        delivery="conditional",
    ),
    BugClass.MISSING_NONCE: _profile(
        "CWE-352",
        "authorization_workflow",
        "cross_site_request_forgery",
        "authorization_workflows",
        surfaces=("entry_point",),
        owasp="A01:2021-Broken Access Control",
        template="state_change.py.j2",
        oracles=("file_effect", "state_change"),
        patchstack="qualifying_csrf",
        delivery="conditional",
    ),
    BugClass.SQLI: _profile(
        "CWE-89",
        "database_injection",
        "sql_injection",
        "injection_files",
        surfaces=("sql_query", "sql_write"),
        owasp="A03:2021-Injection",
        template="sqli_timebased.py.j2",
        oracles=("response_marker", "timing"),
        wordfence="direct",
        patchstack="direct",
    ),
    BugClass.COMMAND_INJECTION: _profile(
        "CWE-78",
        "command_code_injection",
        "command_injection",
        "injection_files",
        surfaces=("command_execution",),
        owasp="A03:2021-Injection",
        template="auth_bypass.py.j2",
        template_fit="generic",
        oracles=("file_effect", "response_marker", "state_change"),
        wordfence="direct",
        patchstack="direct",
        analysis="partial",
        delivery="conditional",
    ),
    BugClass.PATH_TRAVERSAL: _profile(
        "CWE-22",
        "file_access",
        "path_traversal_or_file_access",
        "injection_files",
        surfaces=("dynamic_include", "file_read", "file_delete"),
        owasp="A01:2021-Broken Access Control",
        template="path_traversal.py.j2",
        oracles=("file_effect", "response_marker"),
        wordfence="direct",
        patchstack="direct",
    ),
    BugClass.ARBITRARY_FILE_WRITE: _profile(
        "CWE-434",
        "file_access",
        "arbitrary_file_upload_or_write",
        "injection_files",
        surfaces=("file_upload", "file_write", "file_delete", "file_read"),
        owasp="A01:2021-Broken Access Control",
        template="file_upload.py.j2",
        template_fit="narrow",
        oracles=("file_effect", "response_marker"),
        wordfence="direct",
        patchstack="direct",
        delivery="conditional",
    ),
    BugClass.SSRF: _profile(
        "CWE-918",
        "server_side_request",
        "server_side_request_forgery",
        "injection_files",
        surfaces=("external_http",),
        owasp="A10:2021-Server-Side Request Forgery",
        template="ssrf.py.j2",
        oracles=("authorization", "callback", "response_marker", "state_change"),
        patchstack="concrete_ssrf",
        delivery="conditional",
    ),
    BugClass.XXE: _profile(
        "CWE-611",
        "server_side_parser",
        "xml_external_entity_injection",
        "injection_files",
        surfaces=("xml_parse",),
        owasp="A05:2021-Security Misconfiguration",
        template="auth_bypass.py.j2",
        template_fit="generic",
        oracles=("callback", "file_effect", "response_marker"),
        analysis="review_only",
        delivery="manual",
    ),
    BugClass.PHP_OBJECT_INJECTION: _profile(
        "CWE-502",
        "server_side_parser",
        "php_object_injection",
        "injection_files",
        surfaces=(
            "deserialization",
            "implicit_deserialization",
        ),
        owasp="A08:2021-Software and Data Integrity Failures",
        template="php_object_instantiation.py.j2",
        oracles=("object_instantiation",),
        wordfence="usable_gadget",
        patchstack="direct",
        analysis="partial",
        delivery="conditional",
        critic_evidence_contract=_PHP_OBJECT_INJECTION_CRITIC_EVIDENCE_CONTRACT,
    ),
    BugClass.XSS_REFLECTED: _profile(
        "CWE-79",
        "cross_site_scripting",
        "reflected_cross_site_scripting",
        "xss_lifecycle",
        surfaces=("entry_point", "dom_html"),
        owasp="A03:2021-Injection",
        template="stored_xss.py.j2",
        template_fit="generic",
        oracles=("browser_execution",),
        wordfence="direct",
        patchstack="direct",
        delivery="conditional",
    ),
    BugClass.XSS_STORED: _profile(
        "CWE-79",
        "cross_site_scripting",
        "stored_cross_site_scripting",
        "xss_lifecycle",
        surfaces=(
            "entry_point",
            "sql_write",
            "option_write",
            "object_write",
            "dom_html",
        ),
        owasp="A03:2021-Injection",
        template="stored_xss.py.j2",
        oracles=("browser_execution",),
        wordfence="direct",
        patchstack="sitewide_stored_xss",
        delivery="conditional",
    ),
    BugClass.OPEN_REDIRECT: _profile(
        "CWE-601",
        "intentionally_excluded",
        "open_redirect",
        None,
        owasp="A04:2021-Insecure Design",
        template=None,
        template_fit="none",
        analysis="excluded",
        delivery="none",
        exclusion_reason="Explicitly excluded by specialist and disclosure policy.",
    ),
    BugClass.IDOR: _profile(
        "CWE-639",
        "authorization_workflow",
        "insecure_direct_object_reference",
        "authorization_workflows",
        surfaces=("entry_point", "object_write", "sql_object_access"),
        owasp="A01:2021-Broken Access Control",
        template="idor.py.j2",
        oracles=("cross_object_access",),
        patchstack="significant_object",
        delivery="conditional",
    ),
    BugClass.WEAK_CRYPTO: _profile(
        "CWE-327",
        "cryptography_tokens",
        "practical_cryptographic_bypass",
        "authentication",
        surfaces=("weak_crypto_primitive",),
        owasp="A02:2021-Cryptographic Failures",
        template="auth_bypass.py.j2",
        template_fit="generic",
        oracles=("authorization", "state_change"),
        analysis="review_only",
        delivery="manual",
    ),
    BugClass.WEAK_PRNG: _profile(
        "CWE-338",
        "cryptography_tokens",
        "predictable_security_token",
        "authentication",
        surfaces=("non_cryptographic_randomness",),
        owasp="A02:2021-Cryptographic Failures",
        template="auth_bypass.py.j2",
        template_fit="generic",
        oracles=("authorization", "state_change"),
        analysis="review_only",
        delivery="manual",
    ),
    BugClass.MASS_ASSIGNMENT: _profile(
        "CWE-915",
        "authorization_workflow",
        "mass_assignment",
        "authorization_workflows",
        surfaces=("entry_point", "object_write", "option_write"),
        owasp="A01:2021-Broken Access Control",
        template="state_change.py.j2",
        oracles=("authorization", "state_change"),
        wordfence="qualifying_authorization",
        patchstack="direct",
        delivery="conditional",
    ),
    BugClass.AUTH_BYPASS: _profile(
        "CWE-287",
        "authentication",
        "authentication_bypass",
        "authentication",
        surfaces=("authentication_state",),
        owasp="A07:2021-Identification and Authentication Failures",
        template="auth_bypass.py.j2",
        oracles=("authorization", "state_change"),
        wordfence="direct",
        patchstack="direct",
    ),
    BugClass.MISSING_AUTH_CRITICAL_FUNCTION: _profile(
        "CWE-306",
        "authorization_workflow",
        "missing_authentication_for_critical_function",
        "authorization_workflows",
        surfaces=("entry_point",),
        owasp="A07:2021-Identification and Authentication Failures",
        template="state_change.py.j2",
        template_fit="generic",
        oracles=(
            "authorization",
            "cross_object_access",
            "file_effect",
            "response_marker",
            "state_change",
        ),
        wordfence="qualifying_authorization",
        patchstack="direct",
        delivery="conditional",
    ),
    BugClass.WEAK_PASSWORD_RECOVERY: _profile(
        "CWE-640",
        "authentication",
        "password_recovery_bypass",
        "authentication",
        surfaces=("authentication_state",),
        owasp="A07:2021-Identification and Authentication Failures",
        template="auth_bypass.py.j2",
        template_fit="generic",
        oracles=("authorization", "state_change"),
        analysis="review_only",
        delivery="manual",
    ),
    BugClass.SESSION_FIXATION: _profile(
        "CWE-384",
        "authentication",
        "session_fixation",
        "authentication",
        surfaces=("authentication_state",),
        owasp="A07:2021-Identification and Authentication Failures",
        template="auth_bypass.py.j2",
        template_fit="generic",
        oracles=("authorization",),
        analysis="review_only",
        delivery="manual",
    ),
    BugClass.MISSING_RATE_LIMIT: _profile(
        "CWE-307",
        "intentionally_excluded",
        "missing_rate_limit",
        None,
        owasp="A07:2021-Identification and Authentication Failures",
        template=None,
        template_fit="none",
        analysis="excluded",
        delivery="none",
        exclusion_reason="Rate-limit-only issues are explicitly excluded from active review.",
    ),
    BugClass.RESOURCE_EXHAUSTION: _profile(
        "CWE-400",
        "resource_exhaustion",
        "resource_exhaustion",
        None,
        owasp="A04:2021-Insecure Design",
        template=None,
        template_fit="none",
        analysis="unowned",
        delivery="none",
        exclusion_reason="No bounded automatic denial-of-service verifier is declared.",
    ),
    BugClass.LOGIC_FLAW: _profile(
        "CWE-840",
        "authorization_workflow",
        "security_workflow_bypass",
        "authorization_workflows",
        surfaces=("entry_point", "object_write", "option_write"),
        owasp="A04:2021-Insecure Design",
        template="state_change.py.j2",
        oracles=(
            "authorization",
            "cross_object_access",
            "file_effect",
            "response_marker",
            "state_change",
        ),
        patchstack="direct",
        delivery="conditional",
    ),
}
KNOWN_CWE_REGISTRY: Mapping[BugClass, KnownCWEProfile] = MappingProxyType(
    _KNOWN_CWE_REGISTRY
)


def known_cwe_profile(bug_class: BugClass) -> KnownCWEProfile:
    """Return the explicit profile for a declared, supported taxonomy member."""
    return KNOWN_CWE_REGISTRY[bug_class]


def get_known_cwe_profile(bug_class: BugClass) -> KnownCWEProfile | None:
    """Return support metadata, or ``None`` for an open/unmapped CWE."""
    return KNOWN_CWE_REGISTRY.get(bug_class)


def critic_evidence_contract_for(bug_class: BugClass) -> CriticEvidenceContract:
    """Return a reviewed profile contract or the fail-closed open-CWE fallback."""
    profile = get_known_cwe_profile(bug_class)
    if profile is None:
        return OPEN_CWE_CRITIC_EVIDENCE_CONTRACT
    return profile.critic_evidence_contract
