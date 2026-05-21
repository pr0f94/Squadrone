"""Vulnerability DB clients — Wordfence Intelligence and WPScan, with graceful degradation."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Optional

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

WORDFENCE_FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"


class VulnMatch(BaseModel):
    source: str
    cve_id: Optional[str] = None
    title: str
    affected_versions: str
    bug_class: Optional[str] = None
    published_at: Optional[str] = None
    similarity_score: float = 1.0


def _str_or_none(v: Any) -> Optional[str]:
    if v is None:
        return None
    return str(v)


def _affected_versions_from_software(software_entries: list[dict]) -> str:
    """Build a compact "<= 1.2.3" / "1.0.0 – 1.2.3" string from Wordfence software ranges."""
    parts: list[str] = []
    for sw in software_entries:
        for vrange in sw.get("affected_versions", {}).values():
            frm = vrange.get("from_version") or "*"
            to = vrange.get("to_version") or "*"
            from_inc = vrange.get("from_inclusive")
            to_inc = vrange.get("to_inclusive")
            lo = ("≥" if from_inc else ">") + frm if frm != "*" else None
            hi = ("≤" if to_inc else "<") + to if to != "*" else None
            seg = ", ".join(s for s in (lo, hi) if s)
            if seg:
                parts.append(seg)
    return "; ".join(parts)


def _parse_wordfence(slug: str, payload: Any) -> list[VulnMatch]:
    """Filter Wordfence Intelligence v2 production feed for entries matching `slug`."""
    if not isinstance(payload, dict):
        return []
    matches: list[VulnMatch] = []
    for vuln in payload.values():
        if not isinstance(vuln, dict):
            continue
        software = vuln.get("software") or []
        relevant = [
            sw for sw in software
            if isinstance(sw, dict)
            and sw.get("type") == "plugin"
            and sw.get("slug") == slug
        ]
        if not relevant:
            continue

        cve_id = _str_or_none(vuln.get("cve"))
        if cve_id and not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        cwe = vuln.get("cwe") or {}
        bug_class = None
        if isinstance(cwe, dict):
            cwe_id = cwe.get("id")
            if cwe_id is not None:
                bug_class = f"CWE-{cwe_id}"

        published = vuln.get("published") or vuln.get("date_published")

        matches.append(VulnMatch(
            source="wordfence",
            cve_id=cve_id,
            title=str(vuln.get("title") or f"{slug} vulnerability"),
            affected_versions=_affected_versions_from_software(relevant),
            bug_class=bug_class,
            published_at=_str_or_none(published),
        ))
    return matches


def _parse_wpscan(slug: str, payload: Any) -> list[VulnMatch]:
    if not isinstance(payload, dict):
        return []
    plugin_data = payload.get(slug, payload)
    if not isinstance(plugin_data, dict):
        return []
    items = plugin_data.get("vulnerabilities") or []
    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cve_list = item.get("cve") or []
        cve_id = None
        if isinstance(cve_list, list) and cve_list:
            cve_id = f"CVE-{cve_list[0]}" if not str(cve_list[0]).startswith("CVE-") else str(cve_list[0])
        elif isinstance(cve_list, str) and cve_list:
            cve_id = cve_list if cve_list.startswith("CVE-") else f"CVE-{cve_list}"

        fixed_in = item.get("fixed_in")
        affected = f"<{fixed_in}" if fixed_in else ""

        matches.append(VulnMatch(
            source="wpscan",
            cve_id=cve_id,
            title=str(item.get("title") or f"{slug} vulnerability"),
            affected_versions=affected,
            bug_class=_str_or_none(item.get("vuln_type")),
            published_at=_str_or_none(item.get("created_at") or item.get("published_date")),
        ))
    return matches


class VulnDBClient:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._wordfence_feed: Optional[dict] = None
        self._wordfence_lock = asyncio.Lock()

    async def _get_wordfence_feed(self) -> Optional[dict]:
        if self._wordfence_feed is not None:
            return self._wordfence_feed
        async with self._wordfence_lock:
            if self._wordfence_feed is not None:
                return self._wordfence_feed
            api_key = os.environ.get("WORDFENCE_API_KEY")
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            else:
                logger.warning("WORDFENCE_API_KEY not set — attempting unauthenticated fetch")
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as c:
                    r = await c.get(WORDFENCE_FEED_URL, headers=headers)
            except httpx.HTTPError as e:
                logger.warning("wordfence feed request failed: %s", e)
                return None
            if r.status_code >= 400:
                logger.warning("wordfence feed returned %d", r.status_code)
                return None
            try:
                self._wordfence_feed = r.json()
            except ValueError:
                return None
            return self._wordfence_feed

    async def lookup_wordfence(self, plugin_slug: str) -> list[VulnMatch]:
        feed = await self._get_wordfence_feed()
        if feed is None:
            return []
        return _parse_wordfence(plugin_slug, feed)

    async def lookup_wpscan(self, plugin_slug: str) -> list[VulnMatch]:
        api_key = os.environ.get("WPSCAN_API_KEY")
        if not api_key:
            logger.warning("WPSCAN_API_KEY not set — skipping WPScan lookup")
            return []
        url = f"https://wpscan.com/api/v3/plugins/{plugin_slug}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.get(url, headers={"Authorization": f"Token token={api_key}"})
        except httpx.HTTPError as e:
            logger.warning("wpscan request failed for %s: %s", plugin_slug, e)
            return []
        if r.status_code == 404:
            return []
        if r.status_code >= 400:
            logger.warning("wpscan %s returned %d", plugin_slug, r.status_code)
            return []
        try:
            return _parse_wpscan(plugin_slug, r.json())
        except ValueError:
            return []

    async def lookup_all(self, plugin_slug: str) -> list[VulnMatch]:
        results = await asyncio.gather(
            self.lookup_wordfence(plugin_slug),
            self.lookup_wpscan(plugin_slug),
        )
        merged: dict[str, VulnMatch] = {}
        anon: list[VulnMatch] = []
        for batch in results:
            for m in batch:
                if m.cve_id:
                    if m.cve_id not in merged:
                        merged[m.cve_id] = m
                else:
                    anon.append(m)
        return list(merged.values()) + anon
