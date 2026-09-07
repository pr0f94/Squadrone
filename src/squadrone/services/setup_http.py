"""Runner-owned HTTP addressing for WP-CLI setup postconditions."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _loopback_origin(value: str, *, label: str) -> tuple[SplitResult, str]:
    """Parse one path-free HTTP loopback origin and return its canonical form."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "http"
        or hostname not in _LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a path-free HTTP loopback origin")
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority = f"{authority}:{port}"
    return parsed, f"http://{authority}"


@dataclass(frozen=True, slots=True)
class SetupHttpContext:
    """Minimal network metadata exposed to the setup-planning agent.

    ``internal_connect_origin`` is the address reachable from inside the WordPress
    container. ``canonical_host_header`` is only the HTTP Host authority WordPress
    expects; deliberately retaining no host-facing URL prevents it being selected
    as the connection destination.
    """

    internal_connect_origin: str
    canonical_host_header: str

    def __post_init__(self) -> None:
        _parsed, normalized_origin = _loopback_origin(
            self.internal_connect_origin,
            label="internal setup connect origin",
        )
        if normalized_origin != self.internal_connect_origin:
            raise ValueError("internal setup connect origin is not canonical")
        try:
            _parsed_host, normalized_host_origin = _loopback_origin(
                f"http://{self.canonical_host_header}",
                label="canonical WordPress Host authority",
            )
        except ValueError as exc:
            raise ValueError("canonical WordPress Host authority is invalid") from exc
        if normalized_host_origin.removeprefix("http://") != self.canonical_host_header:
            raise ValueError("canonical WordPress Host authority is not canonical")

    @classmethod
    def from_wordpress_origins(
        cls,
        *,
        internal_connect_origin: str,
        canonical_wordpress_origin: str,
    ) -> "SetupHttpContext":
        """Derive only the safe connect origin and canonical Host authority."""
        _internal, normalized_internal = _loopback_origin(
            internal_connect_origin,
            label="internal setup connect origin",
        )
        canonical, _normalized_canonical = _loopback_origin(
            canonical_wordpress_origin,
            label="canonical WordPress origin",
        )
        hostname = (canonical.hostname or "").lower()
        authority = f"[{hostname}]" if ":" in hostname else hostname
        if canonical.port is not None:
            authority = f"{authority}:{canonical.port}"
        return cls(
            internal_connect_origin=normalized_internal,
            canonical_host_header=authority,
        )
