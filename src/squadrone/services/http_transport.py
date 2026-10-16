"""Canonical fail-closed parsing for source-reviewed HTTP transports."""

from __future__ import annotations

import posixpath
import re
from typing import TypedDict
from urllib.parse import parse_qsl, urlsplit


class HTTPTransport(TypedDict):
    method: str
    route: str
    dispatch: dict[str, str]


HTTPTransportKey = tuple[str, str, tuple[tuple[str, str], ...]]


_HTTP_ENTRY_POINT_RE = re.compile(
    r"^\s*(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+"
    r"(?P<target>/\S*)(?:\s+(?:via\b|->).*)?\s*$",
    re.IGNORECASE,
)
_WORDPRESS_HOOK_ENTRY_POINT_RE = re.compile(
    r"^\s*(?P<prefix>wp_ajax_nopriv_|wp_ajax_|admin_post_nopriv_|admin_post_)"
    r"(?P<action>[A-Za-z0-9_.:-]+)(?:\s+(?:via\b|->).*)?\s*$"
)


def parse_http_transport(entry_point: str) -> HTTPTransport:
    """Parse one exact origin-relative request or standard WordPress hook."""
    fallback: HTTPTransport = {"method": "", "route": "", "dispatch": {}}
    if not isinstance(entry_point, str):
        return fallback

    http_match = _HTTP_ENTRY_POINT_RE.fullmatch(entry_point)
    if http_match:
        raw_target = http_match.group("target")
        if re.search(r"%(?![0-9A-Fa-f]{2})", raw_target):
            return fallback
        parsed = urlsplit(raw_target)
        route = parsed.path
        comparable_route = route[:-1] if route != "/" and route.endswith("/") else route
        if (
            not route.startswith("/")
            or route.startswith("//")
            or "//" in route
            or comparable_route != posixpath.normpath(comparable_route)
            or "%" in route
            or "\\" in route
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
        ):
            return fallback

        try:
            query_pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=64,
            )
        except ValueError:
            return fallback

        query_keys = [key for key, _value in query_pairs]
        if len(query_keys) != len(set(query_keys)) or any(
            not key.strip()
            or key != key.strip()
            or not value.strip()
            or value != value.strip()
            or not key.isascii()
            or not key.isprintable()
            or not value.isascii()
            or not value.isprintable()
            for key, value in query_pairs
        ):
            return fallback
        return {
            "method": http_match.group("method").upper(),
            "route": route,
            "dispatch": {
                f"query:{key}": value
                for key, value in sorted(query_pairs, key=lambda item: item[0])
            },
        }

    hook_match = _WORDPRESS_HOOK_ENTRY_POINT_RE.fullmatch(entry_point)
    if hook_match is None:
        return fallback
    prefix = hook_match.group("prefix")
    route = (
        "/wp-admin/admin-ajax.php"
        if prefix.startswith("wp_ajax_")
        else "/wp-admin/admin-post.php"
    )
    return {
        "method": "POST",
        "route": route,
        "dispatch": {"form:action": hook_match.group("action")},
    }


def canonical_http_transport_key(transport: HTTPTransport) -> HTTPTransportKey:
    """Return the normalized identity used for transport uniqueness checks."""
    return (
        transport["method"],
        transport["route"],
        tuple(sorted(transport["dispatch"].items())),
    )
