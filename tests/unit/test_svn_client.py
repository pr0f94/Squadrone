from __future__ import annotations

import asyncio
import io
import zipfile

import pytest

from squadrone.services.svn import PluginNotFoundError, SVNClient


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


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
async def test_export_zip_404_raises_plugin_not_found(httpx_mock, tmp_path):
    httpx_mock.add_response(
        url="https://downloads.wordpress.org/plugin/missing.1.0.zip",
        status_code=404,
    )

    with pytest.raises(PluginNotFoundError):
        await SVNClient()._export_zip("missing", "1.0", tmp_path / "missing")
