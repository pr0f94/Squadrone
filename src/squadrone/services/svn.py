"""SVN client — pulls plugin source straight from plugins.svn.wordpress.org."""

from __future__ import annotations

import asyncio
import io
import logging
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_SVN_BASE = "https://plugins.svn.wordpress.org"
_PLUGIN_INFO_URL = "https://api.wordpress.org/plugins/info/1.2/"
_PLUGIN_DOWNLOAD_HOST = "downloads.wordpress.org"


class PluginNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class PluginRelease:
    version: str
    download_url: str


@dataclass(frozen=True)
class PluginExport:
    path: str
    source_url: str


def _versioned_download_url(slug: str, version: str) -> str:
    return f"https://downloads.wordpress.org/plugin/{slug}.{version}.zip"


def _svn_target_missing(stderr: str) -> bool:
    """Recognize missing repository paths without masking operational failures."""
    error = stderr.lower()
    if "e160013" in error or "w160013" in error:
        return True
    return "e170000" in error and any(
        marker in error
        for marker in ("doesn't exist", "non-existent", "path not found", "target not found")
    )


class SVNClient:
    """Async client for the wordpress.org plugin SVN repository."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def get_latest_release(self, slug: str) -> PluginRelease:
        params = {
            "action": "plugin_information",
            "request[slug]": slug,
            "request[fields][sections]": "0",
            "request[fields][downloadlink]": "1",
        }
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as c:
            r = await c.get(_PLUGIN_INFO_URL, params=params)
        if r.status_code == 404:
            raise PluginNotFoundError(f"plugin {slug!r} not found on wordpress.org")
        r.raise_for_status()

        try:
            payload = r.json()
        except ValueError as exc:
            raise RuntimeError(
                f"wordpress.org returned invalid plugin metadata for {slug!r}"
            ) from exc
        if not isinstance(payload, dict) or payload.get("error"):
            error = payload.get("error") if isinstance(payload, dict) else None
            raise PluginNotFoundError(
                f"plugin {slug!r} not found on wordpress.org"
                + (f": {error}" if error else "")
            )

        version = payload.get("version")
        download_url = payload.get("download_link")
        if not isinstance(version, str) or not version.strip():
            raise RuntimeError(f"wordpress.org metadata for {slug!r} has no version")
        if not isinstance(download_url, str) or not download_url.strip():
            raise RuntimeError(f"wordpress.org metadata for {slug!r} has no download link")
        if urlparse(download_url).hostname != _PLUGIN_DOWNLOAD_HOST:
            raise RuntimeError(
                f"wordpress.org returned an unexpected download host for {slug!r}"
            )

        return PluginRelease(version=version.strip(), download_url=download_url)

    async def export_release(
        self,
        slug: str,
        release: PluginRelease,
        dest: str,
    ) -> str:
        dest_path = Path(dest)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        await self._download_and_extract(slug, release.download_url, dest_path)
        return str(dest_path)

    async def export(self, slug: str, version: str, dest: str) -> str:
        result = await self.export_pinned_release(slug, version, dest)
        return result.path

    async def export_pinned_release(
        self,
        slug: str,
        version: str,
        dest: str,
    ) -> PluginExport:
        url = f"{_SVN_BASE}/{slug}/tags/{version}"
        dest_path = Path(dest)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            proc = await asyncio.create_subprocess_exec(
                "svn", "export", "--force", url, str(dest_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.warning("svn executable not found; falling back to plugin zip download")
            await self._export_zip(slug, version, dest_path)
            return PluginExport(
                path=str(dest_path),
                source_url=_versioned_download_url(slug, version),
            )

        _stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            if _svn_target_missing(err):
                logger.warning(
                    "SVN tag missing for %s %s; falling back to versioned plugin zip",
                    slug,
                    version,
                )
                await self._export_zip(slug, version, dest_path)
                return PluginExport(
                    path=str(dest_path),
                    source_url=_versioned_download_url(slug, version),
                )
            raise RuntimeError(f"svn export failed: {err.strip()}")
        return PluginExport(path=str(dest_path), source_url=url)

    async def _export_zip(self, slug: str, version: str, dest_path: Path) -> None:
        url = _versioned_download_url(slug, version)
        await self._download_and_extract(slug, url, dest_path, version=version)

    async def _download_and_extract(
        self,
        slug: str,
        url: str,
        dest_path: Path,
        *,
        version: str | None = None,
    ) -> None:
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as c:
            r = await c.get(url)
        if r.status_code == 404:
            target = f" version {version!r}" if version else ""
            raise PluginNotFoundError(
                f"plugin {slug!r}{target} zip not found on wordpress.org"
            )
        r.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            members = zf.infolist()
            if not members:
                raise RuntimeError(f"unexpected plugin zip layout for {slug!r}")
            has_plugin_file = False
            for member in members:
                member_path = Path(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RuntimeError(f"unsafe path in plugin zip for {slug!r}")
                if not member_path.parts or member_path.parts[0] != slug:
                    raise RuntimeError(f"unexpected plugin zip layout for {slug!r}")
                if len(member_path.parts) == 1:
                    if not member.is_dir():
                        raise RuntimeError(f"unexpected plugin zip layout for {slug!r}")
                elif not member.is_dir():
                    has_plugin_file = True
            if not has_plugin_file:
                raise RuntimeError(f"unexpected plugin zip layout for {slug!r}")

            tmp_dest = dest_path.parent / f".{dest_path.name}.zip-extract"
            if tmp_dest.exists():
                shutil.rmtree(tmp_dest)
            tmp_dest.mkdir(parents=True)

            try:
                for member in members:
                    zf.extract(member, tmp_dest)
                extracted = tmp_dest / slug
                if not extracted.is_dir():
                    raise RuntimeError(f"plugin zip for {slug!r} did not contain {slug}/")
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                shutil.move(str(extracted), str(dest_path))
            finally:
                shutil.rmtree(tmp_dest, ignore_errors=True)

    async def get_readme(self, slug: str) -> str:
        url = f"{_SVN_BASE}/{slug}/trunk/readme.txt"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as c:
            r = await c.get(url)
        if r.status_code == 404:
            raise PluginNotFoundError(f"plugin {slug!r} readme.txt not found")
        r.raise_for_status()
        return r.text
