"""SQLite connection helpers with batch-scan friendly defaults."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

import aiosqlite


@asynccontextmanager
async def connect_sqlite(path: str, *, timeout_s: float = 30.0) -> AsyncIterator[aiosqlite.Connection]:
    """Open SQLite with WAL and a busy timeout.

    Squadrone writes from concurrent batch scan tasks. WAL plus busy_timeout
    avoids transient `database is locked` failures without changing callers.
    """
    db = await aiosqlite.connect(path, timeout=timeout_s)
    try:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=30000")
        await db.execute("PRAGMA foreign_keys=ON")
        yield db
    finally:
        await db.close()
