"""WordPress core source cache.

Downloads WP core release zip once, caches at cache/wp-core/<version>/, returns the path.
Used by intake stage 1 #1 (bundle_wp_core) so downstream stages can grep WP internals
to verify claims about WP function behaviour rather than recall from training data.
"""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

CACHE_ROOT = Path("cache/wp-core")
LATEST_URL = "https://wordpress.org/latest.zip"


def _versioned_url(version: str) -> str:
    if version == "latest":
        return LATEST_URL
    return f"https://wordpress.org/wordpress-{version}.zip"


async def ensure_wp_core_cached(version: str = "latest") -> Path | None:
    """Ensure cache/wp-core/<version>/wordpress/ contains WP core source.

    Returns the path to the wordpress/ directory inside the cache, or None on failure.
    Idempotent: skips download if cache already populated.
    Fault-tolerant: logs and returns None on network/zip errors instead of raising
    (so intake doesn't fail the whole scan if the cache step fails).
    """
    target = CACHE_ROOT / version
    wp_dir = target / "wordpress"
    if wp_dir.exists() and any(wp_dir.iterdir()):
        logger.info("wp_core: cache hit at %s", wp_dir)
        return wp_dir

    target.mkdir(parents=True, exist_ok=True)
    url = _versioned_url(version)
    logger.info("wp_core: fetching %s …", url)
    try:
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.content
    except Exception as e:
        logger.warning("wp_core: download failed (%s) — continuing without WP core cache", e)
        return None

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(target)
    except zipfile.BadZipFile as e:
        logger.warning("wp_core: bad zip (%s) — continuing without WP core cache", e)
        return None

    if wp_dir.exists():
        logger.info("wp_core: cached %d top-level entries at %s",
                    sum(1 for _ in wp_dir.iterdir()), wp_dir)
        return wp_dir
    logger.warning("wp_core: zip extracted but no wordpress/ dir found in %s", target)
    return None
