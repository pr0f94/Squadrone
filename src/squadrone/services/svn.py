"""SVN client — pulls plugin source straight from plugins.svn.wordpress.org."""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_SVN_BASE = "https://plugins.svn.wordpress.org"
_TAG_HREF = re.compile(r'<a\s+href="([^"]+?)/?">', re.IGNORECASE)


class PluginNotFoundError(LookupError):
    pass


def _version_key(v: str) -> tuple:
    parts = []
    for piece in v.split("."):
        m = re.match(r"^(\d+)(.*)$", piece)
        if m:
            parts.append((int(m.group(1)), m.group(2)))
        else:
            parts.append((-1, piece))
    return tuple(parts)


class SVNClient:
    """Async client for the wordpress.org plugin SVN repository."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def get_latest_version(self, slug: str) -> str:
        url = f"{_SVN_BASE}/{slug}/tags/"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as c:
            r = await c.get(url)
        if r.status_code == 404:
            raise PluginNotFoundError(f"plugin {slug!r} not found on wordpress.org")
        r.raise_for_status()

        tags = [
            href for href in _TAG_HREF.findall(r.text)
            if href not in ("..",) and not href.startswith("/")
        ]
        if not tags:
            raise PluginNotFoundError(f"plugin {slug!r} has no tags")
        return max(tags, key=_version_key)

    async def export(self, slug: str, version: str, dest: str) -> str:
        url = f"{_SVN_BASE}/{slug}/tags/{version}"
        dest_path = Path(dest)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        proc = await asyncio.create_subprocess_exec(
            "svn", "export", "--force", url, str(dest_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            if "non-existent" in err.lower() or "404" in err:
                raise PluginNotFoundError(
                    f"plugin {slug!r} version {version!r} not found: {err.strip()}"
                )
            raise RuntimeError(f"svn export failed: {err.strip()}")
        return str(dest_path)

    async def get_readme(self, slug: str) -> str:
        url = f"{_SVN_BASE}/{slug}/trunk/readme.txt"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as c:
            r = await c.get(url)
        if r.status_code == 404:
            raise PluginNotFoundError(f"plugin {slug!r} readme.txt not found")
        r.raise_for_status()
        return r.text
