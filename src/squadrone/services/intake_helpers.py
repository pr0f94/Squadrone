"""WordPress.org eligibility checks used during intake."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

WPORG_INFO_URL = "https://api.wordpress.org/plugins/info/1.2/"


async def is_plugin_closed(slug: str) -> bool | None:
    """Return closure state, or ``None`` when WordPress.org cannot be checked."""
    params = {
        "action": "plugin_information",
        "request[slug]": slug,
        "request[fields][sections]": "0",
    }
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(WPORG_INFO_URL, params=params)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("intake: could not check closure state for %s (%s)", slug, exc)
        return None

    return bool(isinstance(data, dict) and (data.get("error") or data.get("closed_date")))
