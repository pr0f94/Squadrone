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
            return str(dest_path)

        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            if "non-existent" in err.lower() or "404" in err:
                raise PluginNotFoundError(
                    f"plugin {slug!r} version {version!r} not found: {err.strip()}"
                )
            raise RuntimeError(f"svn export failed: {err.strip()}")
        return str(dest_path)

    async def _export_zip(self, slug: str, version: str, dest_path: Path) -> None:
        url = f"https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
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
            top_dirs = {
                name.split("/", 1)[0]
                for name in (m.filename for m in members)
                if name and not name.startswith("/") and "/" in name
            }
            if len(top_dirs) != 1:
                raise RuntimeError(f"unexpected plugin zip layout for {slug!r}")
            top_dir = next(iter(top_dirs))

            if dest_path.exists():
                shutil.rmtree(dest_path)
            tmp_dest = dest_path.parent / f".{dest_path.name}.zip-extract"
            if tmp_dest.exists():
                shutil.rmtree(tmp_dest)
            tmp_dest.mkdir(parents=True)

            try:
                for member in members:
                    member_path = Path(member.filename)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        raise RuntimeError(f"unsafe path in plugin zip for {slug!r}")
                    zf.extract(member, tmp_dest)
                extracted = tmp_dest / top_dir
                if not extracted.is_dir():
                    raise RuntimeError(f"plugin zip for {slug!r} did not contain {top_dir}/")
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
