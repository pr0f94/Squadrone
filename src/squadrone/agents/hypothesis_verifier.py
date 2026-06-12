"""Hypothesis verifier — cheap per-hypothesis sanity check after specialists."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional

from pydantic import BaseModel

from ..schemas.hypothesis import Hypothesis
from .prompts_io import load_prompt

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)

CACHE_DIR = Path("cache/verifier")

# V5: 5-state categorisation. Legacy binary "keep"/"drop" still accepted from older clients.
VerdictType = Literal[
    "keep",                         # legacy
    "drop",                         # legacy
    "keep_high_confidence",         # V5: bug shape real, evidence cited
    "keep_conditional",             # V5: real shape, depends on cited external factor (e.g. nonce reachability)
    "keep_insufficient_evidence",   # V5: verifier could not inspect enough source; defer downstream
    "drop_definitely_not_a_bug",    # V5: explicit upstream guard cited
    "escalate_to_manual_review",    # V5: verifier confidence too low, route to human queue
]


class VerifierVerdict(BaseModel):
    verdict: VerdictType
    reason: str
    # V3: optional citation field for "drop reasons must cite file:line"
    citation: Optional[str] = None


# Matches the callback portion of WP-style registrations:
#   [&$this, 'methodName']  → group 1 = methodName
#   array($this, "methodName")  → group 2 = methodName
#   'callback' => 'methodName'  → group 3 = methodName  (REST route)
# Anchored to the callback construct only, NOT to the action-name string.
_CALLBACK_RE = re.compile(
    r"""(?:
        \[\s*[&]?\$this\s*,\s*['"]([A-Za-z_]\w*)['"]\s*\]      # [&$this, 'method']
      | array\s*\(\s*[&]?\$this\s*,\s*['"]([A-Za-z_]\w*)['"]\s*\) # array($this, 'method')
      | ['"]callback['"]\s*=>\s*['"]([A-Za-z_]\w*)['"]          # 'callback' => 'method'
    )""",
    re.VERBOSE,
)


def _resolve_path(plugin_root: Path, rel_file: str) -> Path | None:
    candidate = plugin_root / rel_file
    if candidate.is_file():
        return candidate
    for prefix in ("wp-content/plugins/" + plugin_root.name + "/", plugin_root.name + "/"):
        if rel_file.startswith(prefix):
            candidate = plugin_root / rel_file[len(prefix):]
            if candidate.is_file():
                return candidate
    return None


def _read_lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _slice_around(lines: list[str], line_1based: int, ctx: int = 15) -> str:
    start = max(0, line_1based - 1 - ctx)
    end = min(len(lines), line_1based - 1 + ctx)
    return "\n".join(f"{i+1:5}  {lines[i]}" for i in range(start, end))


def _find_method_definition(lines: list[str], method_name: str) -> int | None:
    """Find the 1-based line number of `function methodName(` or `function & methodName(`."""
    pat = re.compile(rf"\bfunction\s*&?\s*{re.escape(method_name)}\s*\(")
    for i, line in enumerate(lines):
        if pat.search(line):
            return i + 1
    return None


def _read_source_slice(plugin_root: Path, rel_file: str, line: int, ctx: int = 15) -> str | None:
    if not rel_file:
        return None
    path = _resolve_path(plugin_root, rel_file)
    if path is None:
        return None
    lines = _read_lines(path)
    if lines is None:
        return None
    return _slice_around(lines, line, ctx)


def _normalise(text: str) -> str:
    """Collapse whitespace for fuzzy substring comparison."""
    return re.sub(r"\s+", " ", text).strip()


def _find_sink_code_line(lines: list[str], sink_code: str, exclude_line: int | None = None) -> int | None:
    """Search the file for the line where sink_code's first non-trivial fragment appears.

    Whitespace-normalised match against ~80 chars of sink_code. Skips the cited line
    so we find the *real* location, not the (wrong) cited one.
    """
    needle = _normalise(sink_code)[:80]
    if len(needle) < 12:
        return None
    for i, line in enumerate(lines):
        if exclude_line is not None and i + 1 == exclude_line:
            continue
        if needle in _normalise(line):
            return i + 1
    return None


def _read_source_slice_with_handler_followup(
    plugin_root: Path,
    rel_file: str,
    line: int,
    sink_code: str,
    ctx: int = 15,
) -> str | None:
    """Read ±ctx lines around `line`. Apply two recovery strategies if the sink_code
    isn't visible in the primary slice:

    1. **Sink-code search**: scan the file for the actual location of sink_code and
       append a slice around it. This rescues line-number drift (specialist cited
       wrong line but the bug exists nearby in the same file).
    2. **Handler followup**: if the slice contains an `add_action`/`register_rest_route`
       callback registration, find the method definition and append a slice around it.

    Both recoveries can fire — they're complementary."""
    if not rel_file:
        return None
    path = _resolve_path(plugin_root, rel_file)
    if path is None:
        return None
    lines = _read_lines(path)
    if lines is None:
        return None
    primary = _slice_around(lines, line, ctx)
    appended_sections: list[str] = []

    if not sink_code or len(sink_code.strip()) < 8:
        return primary

    sink_in_primary = _normalise(sink_code)[:80] in _normalise(primary)

    # Recovery 1: line-number drift. If sink_code isn't in the primary slice, search
    # the file for its actual location and append a slice around it.
    if not sink_in_primary:
        actual_line = _find_sink_code_line(lines, sink_code, exclude_line=line)
        if actual_line is not None and abs(actual_line - line) > ctx:
            appended_sections.append(
                f"\n\n--- sink_code actually appears at line {actual_line} "
                f"(specialist cited {line}; line-number drift) ---\n"
                + _slice_around(lines, actual_line, ctx)
            )
            sink_in_primary = True  # we've now surfaced it

    # Recovery 2: handler followup. Look for a callback registration on the cited line
    # or anywhere in the primary slice, find the method definition, and append it.
    if not sink_in_primary:
        cited_line_text = lines[line - 1] if 0 < line <= len(lines) else ""
        match = _CALLBACK_RE.search(cited_line_text) or _CALLBACK_RE.search(primary)
        if match:
            method_name = next((g for g in match.groups() if g), None)
            if method_name:
                method_line = _find_method_definition(lines, method_name)
                if method_line is not None:
                    appended_sections.append(
                        f"\n\n--- handler implementation: {method_name}() at line {method_line} ---\n"
                        + _slice_around(lines, method_line, ctx=25)
                    )

    return primary + "".join(appended_sections)


def _verifier_cache_key(hyp: Hypothesis, plugin_version: str, prompt_version: str) -> str:
    """Stable cache key for V7 verifier caching."""
    payload = json.dumps(
        {
            "hyp": hyp.model_dump(mode="json"),
            "plugin_version": plugin_version,
            "prompt_version": prompt_version,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _verifier_cache_load(key: str) -> VerifierVerdict | None:
    p = CACHE_DIR / f"{key}.json"
    if not p.exists():
        return None
    try:
        return VerifierVerdict.model_validate_json(p.read_text())
    except (OSError, ValueError):
        return None


def _verifier_cache_save(key: str, verdict: VerifierVerdict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{key}.json").write_text(verdict.model_dump_json(indent=2))


class HypothesisVerifier:
    NAME = "hypothesis_verifier"
    PROMPT = "hypothesis_verifier"

    def __init__(
        self,
        runtime: "AgentRuntime",
        model: str,
        *,
        wp_idioms_enabled: bool = False,            # V4 + X2
        require_citation: bool = False,             # V3
        drop_categorisation_enabled: bool = False,  # V5
        iterative_enabled: bool = False,            # V1
        max_iterations: int = 3,                    # V1
        cache_enabled: bool = False,                # V7
        plugin_version: str = "",                   # for cache key
    ):
        self.runtime = runtime
        self.model = model
        self.wp_idioms_enabled = wp_idioms_enabled
        self.require_citation = require_citation
        self.drop_categorisation_enabled = drop_categorisation_enabled
        self.iterative_enabled = iterative_enabled
        self.max_iterations = max_iterations
        self.cache_enabled = cache_enabled
        self.plugin_version = plugin_version

    def _build_system_prompt(self) -> str:
        parts = [load_prompt(self.PROMPT)]
        if self.wp_idioms_enabled:
            parts.append("\n\n# Reference: WordPress idioms\n\n" + load_prompt("_wp_idioms"))
        if self.require_citation:
            parts.append(
                "\n\n# V3: Citation requirement\n\n"
                "Every load-bearing claim in `reason` MUST cite `file:line` and quote the line. "
                "If you can't cite enough evidence to prove a drop, use "
                "`keep_insufficient_evidence` or `escalate_to_manual_review` "
                "(NOT `drop_definitely_not_a_bug`). "
                "Conservative drops with 'I can't see X' framing are reliable; confident "
                "drops with concrete-but-uncited claims about WP internals are the failure mode."
            )
        if self.drop_categorisation_enabled:
            parts.append(
                "\n\n# V5: Five-state verdict\n\n"
                "Use one of these verdicts (NOT the legacy `keep`/`drop`):\n"
                "- `keep_high_confidence` — bug shape real, evidence cited\n"
                "- `keep_conditional` — bug shape real, depends on a cited external factor "
                "(e.g. nonce reachability); explain the condition in `reason`\n"
                "- `keep_insufficient_evidence` — source slice/tooling was insufficient; "
                "defer to triage/verification instead of dropping\n"
                "- `drop_definitely_not_a_bug` — only when the sink is hallucinated, the "
                "bug class is impossible from the cited source, or an explicit upstream "
                "guard is cited at file:line\n"
                "- `escalate_to_manual_review` — your confidence is below threshold; route to human"
            )
        return "".join(parts)

    def _prompt_version(self) -> str:
        flags = (self.wp_idioms_enabled, self.require_citation,
                 self.drop_categorisation_enabled, self.iterative_enabled)
        return "cwe-plausibility-v2:" + ":".join("1" if f else "0" for f in flags)

    async def verify(self, hyp: Hypothesis, plugin_path: str) -> VerifierVerdict:
        # V7: cache check
        cache_key: str | None = None
        if self.cache_enabled:
            cache_key = _verifier_cache_key(hyp, self.plugin_version, self._prompt_version())
            cached = _verifier_cache_load(cache_key)
            if cached is not None:
                return cached

        plugin_root = Path(plugin_path)
        slice_text = _read_source_slice_with_handler_followup(
            plugin_root, hyp.file, hyp.line, hyp.sink_code or ""
        )
        if slice_text is None:
            # Can't read the file — keep by default; let triage/verify handle it.
            verdict = VerifierVerdict(
                verdict="keep_insufficient_evidence" if self.drop_categorisation_enabled else "keep",
                reason="source file not found on disk; deferring to triage",
            )
            if cache_key:
                _verifier_cache_save(cache_key, verdict)
            return verdict

        system = self._build_system_prompt()
        user = (
            f"HYPOTHESIS:\n{hyp.model_dump_json(indent=2)}\n\n"
            f"SOURCE_SLICE ({hyp.file} around line {hyp.line}):\n```\n{slice_text}\n```"
        )

        # V1: iterative tool-enabled verifier — let it call read_plugin_file across N rounds
        # before deciding. Reuses the existing tool infra.
        tools = None
        if self.iterative_enabled:
            from .tools import READ_PLUGIN_FILE_TOOL
            tools = [READ_PLUGIN_FILE_TOOL]

        run_kwargs: dict = {
            "agent_name": self.NAME,
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "output_schema": VerifierVerdict,
        }
        if self.iterative_enabled:
            run_kwargs["tools"] = tools
            run_kwargs["max_iterations"] = self.max_iterations + 1  # +1 for the final no-tool decision

        try:
            result = await self.runtime.run(**run_kwargs)
            verdict = result.output
        except Exception as e:
            logger.warning("verifier: %s — keeping hypothesis %s by default", e, hyp.id)
            verdict = VerifierVerdict(verdict="keep", reason=f"verifier error: {e}")

        if cache_key:
            _verifier_cache_save(cache_key, verdict)
        return verdict
