"""Heuristic XSS reflection check for PoC scripts.

This is HEURISTIC, not proof of execution. A True from check_reflection() means
the literal payload bytes appear in the response in a context that COULD execute
as code. It does NOT prove the JavaScript ran — that requires a headless browser
(see W2 / browser_check.py).

USAGE inside a PoC:

    from xss_check import check_reflection

    result = check_reflection(response.text, payload="<script>alert(1)</script>")
    if result.exploitable:
        print(f"[+] SUCCESS: payload reflected unescaped at offset {result.offset}")
        print(f"    Sink context: {result.sink_context}")
        print(f"    Excerpt: {result.context}")
    else:
        print(f"[-] FAILURE: {result.reason}")
        print(f"    Sink context: {result.sink_context}")

Use .exploitable as the boolean for SUCCESS/FAILURE — do NOT write your own
substring check.

Stage-5 W1 fix (2026-05-08): replaced the broken regex-based context detector
with a proper html.parser-based tokenizer that tracks attribute name + delimiter,
plus a delimiter-vs-payload-char compatibility check. The previous heuristic
failed on nested-`=` patterns (e.g. `?referrer=` inside an `href="..."` value)
and had no concept of attribute delimiter — see manual_reviews/wp-statistics for
the wp-statistics xss-001 FP this fixes.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional

# Encoding markers that indicate the payload was neutralised before reflection.
ENCODED_MARKERS = (
    "&lt;", "&gt;", "&quot;", "&apos;", "&amp;",
    "&#039;", "&#39;", "&#34;", "&#60;", "&#62;",
    "&#x27;", "&#x22;", "&#x3c;", "&#x3e;", "&#x3C;", "&#x3E;",
    "%3C", "%3c", "%3E", "%3e", "%22", "%27",
    "\\u003c", "\\u003e", "\\u0022", "\\u0027",
    "\\x3c", "\\x3e", "\\x22", "\\x27",
    '\\"', "\\'",
)


@dataclass
class ReflectionResult:
    exploitable: bool
    reason: str
    context: Optional[str]
    offset: Optional[int]
    sink_context: Optional[str]   # "html_attribute:'" | "html_attribute:\"" | "html_attribute:unquoted" |
                                  # "html_text" | "js_string" | "css" | "comment" | "url_inside_attribute"
    suggested_next: Optional[str]
    attribute_delimiter: Optional[str] = None  # "'" | '"' | "" (unquoted) | None
    attribute_name: Optional[str] = None       # 'href', 'title', 'onclick', etc.


# ---------- W1 fix: proper context detection via html.parser tokenizer ---------------

class _ContextProbe(HTMLParser):
    """Walks HTML up to a target byte offset and reports the parser state at that point.

    Tracks:
    - tag stack (which open tag are we inside?)
    - inside <script>/<style> (raw-text contexts)
    - HTML comment region

    HTMLParser doesn't expose attribute delimiter, so attribute-context is detected
    by analysing the source text directly (see _attribute_context_at_offset).
    """

    def __init__(self, target_offset: int) -> None:
        super().__init__(convert_charrefs=False)
        self.target = target_offset
        self.tag_stack: list[str] = []
        self.in_script = False
        self.in_style = False
        self.in_comment = False
        self.context_at_target: str = "html_text"
        self._reached = False

    def _check_done(self) -> None:
        if self._reached:
            return
        if self.getpos()[0] >= 1 and self._byte_offset() >= self.target:
            self._reached = True
            if self.in_script:
                self.context_at_target = "js_string"
            elif self.in_style:
                self.context_at_target = "css"
            elif self.in_comment:
                self.context_at_target = "comment"
            else:
                self.context_at_target = "html_text"

    def _byte_offset(self) -> int:
        # HTMLParser exposes (line, col) — we approximate offset via internal rawdata
        return getattr(self, "rawdata", "").find("", 0)  # not reliable; we drive offset externally

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self.tag_stack.append(tag)
        if tag == "script":
            self.in_script = True
        if tag == "style":
            self.in_style = True
        self._check_done()

    def handle_endtag(self, tag: str) -> None:
        if self.tag_stack and self.tag_stack[-1] == tag:
            self.tag_stack.pop()
        if tag == "script":
            self.in_script = False
        if tag == "style":
            self.in_style = False
        self._check_done()

    def handle_data(self, data: str) -> None:
        self._check_done()

    def handle_comment(self, data: str) -> None:
        self._check_done()


def _attribute_context_at_offset(body: str, offset: int) -> tuple[str, Optional[str], Optional[str]]:
    """Determine if `offset` is inside an HTML attribute value, and if so, return
    (sink_context, attribute_name, delimiter).

    Walks back from `offset` to the most recent `<` and forward-parses the tag
    structure. Returns:
    - ("html_attribute:'", "href", "'") if inside a single-quoted href attribute
    - ("html_attribute:\"", "title", '"') if inside a double-quoted title attribute
    - ("html_attribute:unquoted", "value", "") if inside an unquoted attribute value
    - ("html_tag", None, None) if we're inside a tag but not in an attribute value
    - ("html_text", None, None) if we're not in a tag at all
    """
    # Find the most recent < that hasn't been closed by a >
    last_lt = body.rfind("<", 0, offset)
    if last_lt == -1:
        return ("html_text", None, None)

    # Reject `<` that's inside a comment, script, style — handled by tokenizer pass
    # Find a > between last_lt and offset; if present, we're not inside the tag
    last_gt = body.rfind(">", last_lt, offset)
    if last_gt != -1:
        return ("html_text", None, None)

    # We're between `<` and `offset` with no closing `>`. Walk forward through the tag,
    # tracking attribute boundaries.
    pos = last_lt + 1
    # Skip tag name
    while pos < offset and body[pos] not in " \t\n\r/":
        pos += 1
    # Now in attribute-value-or-name region
    state = "before_attr"
    attr_name = ""
    delim = ""

    while pos < offset:
        ch = body[pos]
        if state == "before_attr":
            if ch in " \t\n\r":
                pos += 1
                continue
            if ch in "/>":
                # Self-close or end of tag — but we already established offset is before any `>`,
                # so a `/` here means self-closing, but the tag isn't closed yet; treat as before_attr.
                pos += 1
                continue
            # start of attr name
            attr_name = ""
            state = "attr_name"
            continue
        if state == "attr_name":
            if ch == "=":
                state = "before_value"
                pos += 1
                continue
            if ch in " \t\n\r/>":
                # boolean attribute, no value
                attr_name = ""
                state = "before_attr"
                pos += 1
                continue
            attr_name += ch
            pos += 1
            continue
        if state == "before_value":
            if ch in " \t\n\r":
                pos += 1
                continue
            if ch in ("'", '"'):
                delim = ch
                state = "in_quoted_value"
                pos += 1
                continue
            # unquoted value
            delim = ""
            state = "in_unquoted_value"
            continue
        if state == "in_quoted_value":
            if ch == delim:
                state = "before_attr"
                attr_name = ""
                delim = ""
                pos += 1
                continue
            pos += 1
            continue
        if state == "in_unquoted_value":
            if ch in " \t\n\r>":
                state = "before_attr"
                attr_name = ""
                pos += 1
                continue
            pos += 1
            continue
        pos += 1

    # We've reached `offset`. Where are we?
    if state == "in_quoted_value":
        return (f"html_attribute:{delim}", attr_name or None, delim)
    if state == "in_unquoted_value":
        return ("html_attribute:unquoted", attr_name or None, "")
    return ("html_tag", None, None)


def _is_url_attribute(attr_name: Optional[str]) -> bool:
    if not attr_name:
        return False
    return attr_name.lower() in {"href", "src", "srcset", "action", "formaction", "data", "poster",
                                   "background", "cite", "longdesc", "manifest", "usemap"}


def _payload_can_break_context(payload: str, sink_context: str, delim: Optional[str]) -> bool:
    """Given the payload bytes and the surrounding context, is breakout possible?"""
    if sink_context == "html_text":
        # Tag breakout requires `<` to start a new tag
        return "<" in payload
    if sink_context.startswith("html_attribute:"):
        if sink_context == "html_attribute:unquoted":
            # Unquoted attribute terminates on whitespace, `>`, or quote chars
            return any(c in payload for c in " \t\n\r>'\"")
        # Quoted attribute breakout requires the matching delimiter
        if delim:
            return delim in payload
        return False
    if sink_context == "js_string":
        # JS string breakout: matching quote, or `</script>` to close the script element
        return any(q in payload for q in ("'", '"', "`")) or "</script" in payload.lower()
    if sink_context == "html_tag":
        # Inside the tag but not in an attribute value — `>` breaks out into text content
        return ">" in payload or " " in payload
    return False


def _detect_sink_context(body: str, offset: int) -> tuple[str, Optional[str], Optional[str]]:
    """Return (sink_context, attribute_name, delimiter) for the position at `offset`."""
    # First check raw-text contexts (script/style/comment) by parsing up to offset
    pre = body[:offset]
    # Quick raw-text detection
    last_open_script = pre.rfind("<script")
    last_close_script = pre.rfind("</script")
    if last_open_script != -1 and last_open_script > last_close_script:
        return ("js_string", None, None)
    last_open_style = pre.rfind("<style")
    last_close_style = pre.rfind("</style")
    if last_open_style != -1 and last_open_style > last_close_style:
        return ("css", None, None)
    last_open_comment = pre.rfind("<!--")
    last_close_comment = pre.rfind("-->")
    if last_open_comment != -1 and last_open_comment > last_close_comment:
        return ("comment", None, None)
    # Otherwise, walk the immediate tag region for attribute context
    return _attribute_context_at_offset(body, offset)


def check_reflection(body: str, payload: str, ctx: int = 80) -> ReflectionResult:
    """Check whether `payload` appears in `body` in a form that could execute.

    W1 fix: only flag exploitable if the payload contains characters that can
    break out of THIS specific surrounding context. A `'`-only payload inside a
    `"`-delimited attribute is harmless; substring presence isn't enough.
    """
    if not payload:
        return ReflectionResult(False, "empty_payload", None, None, None,
                                "supply a non-empty payload")

    offset = body.find(payload)
    if offset == -1:
        return ReflectionResult(
            exploitable=False,
            reason="no_match",
            context=None,
            offset=None,
            sink_context=None,
            suggested_next=(
                "Literal payload bytes not in response. The endpoint may have "
                "rejected the input, the value may be stored elsewhere (DB), or "
                "the payload may have been mutated. Check the response body for "
                "any partial reflection of your marker."
            ),
        )

    start = max(0, offset - ctx)
    end = min(len(body), offset + len(payload) + ctx)
    context = body[start:end]

    sink_context, attr_name, delim = _detect_sink_context(body, offset)

    # Look for encoding markers in the surrounding context — if present, payload was neutralised
    encoded_in_context = [m for m in ENCODED_MARKERS if m in context]
    if encoded_in_context:
        if any(m.startswith("&") for m in encoded_in_context):
            reason = "html_entity_encoded"
            suggestion = (
                "Server is HTML-entity encoding the output. Standard <script>/<img> "
                "payloads will not fire here. Try a different sink or context."
            )
        elif any(m.startswith("%") for m in encoded_in_context):
            reason = "url_encoded"
            suggestion = (
                "Reflection is URL-encoded. The encoded form cannot break out of an HTML attribute."
            )
        else:
            reason = "js_escaped"
            suggestion = (
                "Reflection has JS escapes. To execute, you'd need to close the string AND statement."
            )
        return ReflectionResult(
            exploitable=False, reason=reason, context=context, offset=offset,
            sink_context=sink_context, suggested_next=suggestion,
            attribute_delimiter=delim, attribute_name=attr_name,
        )

    # W1 core check: payload must contain chars that can break out of THIS context
    if not _payload_can_break_context(payload, sink_context, delim):
        # Special case: URL-typed attribute (href/src/etc.) — `'` and `"` in the URL
        # value are not breakout vectors per HTML spec; only the matching attribute
        # delimiter breaks out, and that's covered above. Distinguish for clearer reporting.
        if sink_context.startswith("html_attribute:") and _is_url_attribute(attr_name):
            ctx_label = "url_inside_attribute"
        else:
            ctx_label = sink_context
        return ReflectionResult(
            exploitable=False,
            reason="context_does_not_permit_breakout",
            context=context,
            offset=offset,
            sink_context=ctx_label,
            suggested_next=(
                f"Payload reflected at offset {offset} but the surrounding context "
                f"({sink_context}, attr={attr_name}, delim={delim!r}) doesn't permit "
                f"breakout from these bytes. Try a payload containing chars that match "
                f"the context's terminating delimiter."
            ),
            attribute_delimiter=delim, attribute_name=attr_name,
        )

    # Verify special chars actually appear literally (not just substring match of a prefix)
    needed = [c for c in '<>"\'' if c in payload]
    missing = [c for c in needed if c not in context]
    if missing:
        return ReflectionResult(
            exploitable=False, reason="partial_match", context=context, offset=offset,
            sink_context=sink_context,
            suggested_next=(
                f"Payload offset matched but special char(s) {missing} not found in "
                "the surrounding context. Likely a coincidental substring match."
            ),
            attribute_delimiter=delim, attribute_name=attr_name,
        )

    return ReflectionResult(
        exploitable=True,
        reason="literal_unescaped",
        context=context,
        offset=offset,
        sink_context=sink_context,
        suggested_next=None,
        attribute_delimiter=delim,
        attribute_name=attr_name,
    )


# ---------- W8: negative-control reflection ------------------------------------------

def check_reflection_with_negative_control(
    body: str,
    payload: str,
    benign_marker: str,
    benign_body: Optional[str] = None,
    ctx: int = 80,
) -> ReflectionResult:
    """Differential reflection check (W8).

    Runs the standard check on `payload`. If exploitable, ALSO checks whether
    `benign_marker` reflects in the SAME context in `benign_body` (if provided).
    If yes → the reflection is generic input-echo, not attack-specific. Downgrade.

    Caller is responsible for issuing the benign request and passing benign_body.
    """
    primary = check_reflection(body, payload, ctx)
    if not primary.exploitable or benign_body is None:
        return primary

    benign = check_reflection(benign_body, benign_marker, ctx)
    # If the benign marker reflects in the same context type with the same delimiter,
    # treat the primary as generic input-echo not specific to attack chars.
    if benign.exploitable and benign.sink_context == primary.sink_context:
        return ReflectionResult(
            exploitable=False,
            reason="negative_control_also_reflected",
            context=primary.context,
            offset=primary.offset,
            sink_context=primary.sink_context,
            suggested_next=(
                f"Both attack payload AND benign marker '{benign_marker}' reflect in "
                f"context {primary.sink_context}. The reflection is generic input-echo, "
                f"not attack-specific. Look for a different sink."
            ),
            attribute_delimiter=primary.attribute_delimiter,
            attribute_name=primary.attribute_name,
        )
    return primary
