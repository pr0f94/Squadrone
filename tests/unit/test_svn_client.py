from __future__ import annotations

import asyncio
import io
import zipfile
from unittest.mock import AsyncMock

import pytest

from squadrone.services.svn import PluginNotFoundError, PluginRelease, SVNClient


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_latest_release_uses_wordpress_plugin_metadata(httpx_mock):
    httpx_mock.add_response(
        url=(
            "https://api.wordpress.org/plugins/info/1.2/"
            "?action=plugin_information"
            "&request%5Bslug%5D=wp-file-manager"
            "&request%5Bfields%5D%5Bsections%5D=0"
            "&request%5Bfields%5D%5Bdownloadlink%5D=1"
        ),
        json={
            "slug": "wp-file-manager",
            "version": "8.0.4",
            "download_link": (
                "https://downloads.wordpress.org/plugin/wp-file-manager.8.0.4.zip"
            ),
        },
    )

    release = await SVNClient().get_latest_release("wp-file-manager")

    assert release.version == "8.0.4"
    assert release.download_url.endswith("wp-file-manager.8.0.4.zip")


@pytest.mark.asyncio
async def test_export_release_uses_metadata_download_link(httpx_mock, tmp_path):
    download_url = "https://downloads.wordpress.org/plugin/demo.8.0.4.zip"
    httpx_mock.add_response(
        url=download_url,
        content=_zip_bytes({"demo/demo.php": "<?php\n"}),
    )

    client = SVNClient()
    result = await client.export_release(
        "demo",
        PluginRelease(version="8.0.4", download_url=download_url),
        str(tmp_path / "demo"),
    )

    assert result == str(tmp_path / "demo")
    assert (tmp_path / "demo" / "demo.php").read_text() == "<?php\n"


@pytest.mark.asyncio
async def test_export_falls_back_to_wordpress_zip_when_svn_missing(
    monkeypatch,
    httpx_mock,
    tmp_path,
):
    async def missing_svn(*args, **kwargs):
        raise FileNotFoundError("svn")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", missing_svn)
    httpx_mock.add_response(
        url="https://downloads.wordpress.org/plugin/demo.1.2.3.zip",
        content=_zip_bytes({"demo/demo.php": "<?php\n"}),
    )

    dest = tmp_path / "demo"
    result = await SVNClient().export("demo", "1.2.3", str(dest))

    assert result == str(dest)
    assert (dest / "demo.php").read_text() == "<?php\n"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stderr",
    [
        (
            "svn: E170000: URL "
            "'https://plugins.svn.wordpress.org/demo/tags/1.2.3' doesn't exist"
        ),
        (
            "svn: warning: W160013: '/demo/!svn/rvr/1/tags/1.2.3' path not found\n"
            "svn: E200009: Could not display info for all targets"
        ),
    ],
)
async def test_export_falls_back_when_svn_tag_is_missing(
    monkeypatch,
    httpx_mock,
    tmp_path,
    stderr,
):
    class MissingTagProcess:
        returncode = 1

        async def communicate(self):
            return b"", stderr.encode()

    async def missing_tag(*args, **kwargs):
        return MissingTagProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", missing_tag)
    download_url = "https://downloads.wordpress.org/plugin/demo.1.2.3.zip"
    httpx_mock.add_response(
        url=download_url,
        content=_zip_bytes({"demo/demo.php": "<?php\n"}),
    )

    dest = tmp_path / "demo"
    result = await SVNClient().export_pinned_release("demo", "1.2.3", str(dest))

    assert result.path == str(dest)
    assert result.source_url == download_url
    assert (dest / "demo.php").read_text() == "<?php\n"


@pytest.mark.asyncio
async def test_export_does_not_fallback_for_operational_svn_failure(
    monkeypatch,
    tmp_path,
):
    class FailedProcess:
        returncode = 1

        async def communicate(self):
            return b"", b"svn: E175002: Unexpected HTTP status 503 'Service Unavailable'"

    async def failed_export(*args, **kwargs):
        return FailedProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", failed_export)
    client = SVNClient()
    client._export_zip = AsyncMock()  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="E175002"):
        await client.export_pinned_release("demo", "1.2.3", str(tmp_path / "demo"))

    client._export_zip.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "files",
    [
        {"other/demo.php": "<?php\n"},
        {"demo/demo.php": "<?php\n", "README.txt": "unexpected sibling"},
    ],
)
async def test_zip_layout_failure_preserves_existing_destination(
    httpx_mock,
    tmp_path,
    files,
):
    download_url = "https://downloads.wordpress.org/plugin/demo.1.2.3.zip"
    httpx_mock.add_response(url=download_url, content=_zip_bytes(files))
    dest = tmp_path / "demo"
    dest.mkdir()
    (dest / "existing.php").write_text("preserve me\n")

    with pytest.raises(RuntimeError, match="unexpected plugin zip layout"):
        await SVNClient()._export_zip("demo", "1.2.3", dest)

    assert (dest / "existing.php").read_text() == "preserve me\n"


@pytest.mark.asyncio
async def test_export_zip_404_raises_plugin_not_found(httpx_mock, tmp_path):
    httpx_mock.add_response(
        url="https://downloads.wordpress.org/plugin/missing.1.0.zip",
        status_code=404,
    )

    with pytest.raises(PluginNotFoundError):
        await SVNClient()._export_zip("missing", "1.0", tmp_path / "missing")
