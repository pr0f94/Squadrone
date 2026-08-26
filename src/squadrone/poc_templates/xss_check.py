"""Heuristic XSS reflection check for PoC scripts.

This is HEURISTIC, not proof of execution. A True from check_reflection() means
the literal payload bytes appear in the response in a context that COULD execute
as code. It does NOT prove the JavaScript ran — that requires a headless browser
(see browser_check.py).

USAGE inside a PoC:

    from xss_check import check_reflection

    result = check_reflection(response.text, payload="<script>alert(1)</script>")
    if result.exploitable:
        print(f"candidate reflection at offset {result.offset}")
        print(f"    Sink context: {result.sink_context}")
        print(f"    Excerpt: {result.context}")
    else:
        print(f"no candidate reflection: {result.reason}")
        print(f"    Sink context: {result.sink_context}")

Use `.exploitable` only to select a page for browser verification. Do not write
your own substring check and do not treat this diagnostic as proof.
"""

from __future__ import annotations

from dataclasses import dataclass
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

    Only flag exploitable if the payload contains characters that can
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

    # The payload must contain characters that can break out of this context.
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
