from __future__ import annotations

import pytest

from squadrone.services.sqlite import connect_sqlite


@pytest.mark.asyncio
async def test_connect_sqlite_sets_pragmas_and_writes(tmp_path):
    db_path = tmp_path / "test.sqlite"

    async with connect_sqlite(str(db_path)) as db:
        await db.execute("CREATE TABLE demo(id INTEGER PRIMARY KEY, value TEXT)")
        await db.execute("INSERT INTO demo(value) VALUES ('ok')")
        await db.commit()
        async with db.execute("PRAGMA busy_timeout") as cur:
            busy_timeout = (await cur.fetchone())[0]

    async with connect_sqlite(str(db_path)) as db:
        async with db.execute("SELECT value FROM demo") as cur:
            value = (await cur.fetchone())[0]

    assert value == "ok"
    assert busy_timeout >= 30000
