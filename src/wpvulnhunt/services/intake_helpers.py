"""Stage-1 intake helpers: file classification, changelog parsing, closed-plugin detection.

Each helper is independent and tolerates failure (returns None / sane defaults rather
than raising) so intake doesn't fail the whole scan if an opt-in feature errors out.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)


# ---------- #2: file classification ---------------------------------------------------

# Heuristic order matters: more-specific buckets checked first. A file matches the
# first bucket whose pattern hits its relative path; otherwise → "other".
_CLASSIFICATION_RULES: list[tuple[str, list[str]]] = [
    ("vendor", ["vendor/", "node_modules/", "includes/libraries/", "lib/", "third-party/"]),
    ("tests", ["tests/", "test/", "/__tests__/", ".test.php", ".spec.js", ".spec.ts", "phpunit"]),
    ("lang", ["languages/", ".po", ".mo", ".pot"]),
    ("assets", ["assets/", "/dist/", "/build/", "css/", "/img/", "/images/", "/fonts/"]),
    ("admin", ["admin/", "includes/admin/", "wp-admin/", "/dashboard/"]),
    ("frontend", ["front-end/", "frontend/", "public/", "shortcodes/", "templates/"]),
    ("api", ["/api/", "rest/", "/endpoints/"]),
]


def classify_files(plugin_dir: Path) -> dict[str, list[str]]:
    """Bucket every file in plugin_dir by purpose. Returns {bucket: [relpath, ...]}.

    Files matching no rule land in "other". JS/CSS/asset files end up in "assets" rather
    than "frontend" so frontend bucket stays PHP-centric for recon.
    """
    buckets: dict[str, list[str]] = {b: [] for b, _ in _CLASSIFICATION_RULES}
    buckets["other"] = []
    if not plugin_dir.exists():
        return buckets

    for f in plugin_dir.rglob("*"):
        if not f.is_file():
            continue
        rel = str(f.relative_to(plugin_dir))
        rel_lc = "/" + rel.lower()  # leading "/" lets patterns match path components cleanly
        placed = False
        for bucket, patterns in _CLASSIFICATION_RULES:
            if any(p in rel_lc for p in patterns):
                buckets[bucket].append(rel)
                placed = True
                break
        if not placed:
            buckets["other"].append(rel)
    return buckets


# ---------- #4: changelog parsing -----------------------------------------------------

_CHANGELOG_HEADER = re.compile(r"^==\s*Changelog\s*==\s*$", re.IGNORECASE | re.MULTILINE)
_VERSION_HEADER = re.compile(r"^=\s*([0-9][0-9a-z.\-]*)\s*(?:\((\d{4}-\d{2}-\d{2})\))?\s*=\s*$",
                              re.MULTILINE)


def parse_recent_changelog(plugin_dir: Path, max_entries: int = 5) -> list[dict] | None:
    """Parse readme.txt's Changelog section into structured entries.

    Returns up to `max_entries` most-recent versions:
        [{"version": "3.16.0", "date": "2026-04-24" or None, "entries": ["...", "..."]}]
    Returns None if no readme.txt or no Changelog section found.
    """
    readme = plugin_dir / "readme.txt"
    if not readme.exists():
        return None
    try:
        text = readme.read_text(errors="replace")
    except OSError:
        return None

    m = _CHANGELOG_HEADER.search(text)
    if not m:
        return None
    body = text[m.end():]

    # Split body on `= version =` markers
    matches = list(_VERSION_HEADER.finditer(body))
    if not matches:
        return None

    out: list[dict] = []
    for i, vm in enumerate(matches[:max_entries]):
        version = vm.group(1)
        date = vm.group(2)  # may be None
        start = vm.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        chunk = body[start:end].strip()
        # Each entry is typically a bullet line starting with * or -
        entries = []
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith(("==", "= ")):  # next section / version
                break
            if line.startswith(("*", "-")):
                entries.append(line.lstrip("*- ").strip())
            elif entries:
                # Continuation line for the previous entry
                entries[-1] = entries[-1] + " " + line
        out.append({"version": version, "date": date, "entries": entries})
    return out


# ---------- #6: closed-plugin detection ------------------------------------------------

WPORG_INFO_URL = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}"


async def is_plugin_closed(slug: str) -> bool | None:
    """Check wp.org plugin info API. Returns True if closed, False if active, None on error.

    A plugin closed by wp.org admins typically returns:
      - HTTP 200 with `{"error": "Plugin not found."}` (after closure)
      - or fields like `closed_date` set
    """
    url = WPORG_INFO_URL.format(slug=slug)
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            r = await client.get(url)
    except Exception as e:
        logger.warning("is_plugin_closed: %s lookup failed (%s)", slug, e)
        return None

    if r.status_code != 200:
        logger.warning("is_plugin_closed: %s HTTP %d", slug, r.status_code)
        return None
    try:
        data = r.json()
    except ValueError:
        return None

    if isinstance(data, dict) and (data.get("error") or data.get("closed_date")):
        return True
    return False
