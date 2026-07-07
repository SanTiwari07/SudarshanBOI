"""
Sudarshan Database Layer
========================
Async SQLite database using aiosqlite.

Tables:
  - users        → analyst accounts with roles
  - cases        → every APK analysis result
  - ioc_cache    → IOC reputation cache (24h TTL)
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("SUDARSHAN_DB_PATH", "sudarshan.db")

# ─── DDL ─────────────────────────────────────────────────────────────────────

_CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    hashed_pw   TEXT    NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'analyst',   -- analyst | soc_lead | admin
    created_at  TEXT    NOT NULL
);
"""

_CREATE_CASES = """
CREATE TABLE IF NOT EXISTS cases (
    sha256              TEXT    PRIMARY KEY,
    package_name        TEXT,
    app_name            TEXT,
    analysis_mode       TEXT,
    family_classification TEXT,
    final_risk_score    REAL,
    risk_band           TEXT,
    confidence          REAL,
    dynamic_available   INTEGER DEFAULT 0,
    obfuscation_score   REAL    DEFAULT 0.0,
    has_reflection      INTEGER DEFAULT 0,
    frs_breakdown       TEXT,    -- JSON
    threat_scenario_table TEXT,  -- JSON
    intelligence_report TEXT,    -- JSON
    analyst_id          INTEGER,
    created_at          TEXT    NOT NULL,
    FOREIGN KEY (analyst_id) REFERENCES users(id)
);
"""

_CREATE_IOC_CACHE = """
CREATE TABLE IF NOT EXISTS ioc_cache (
    indicator   TEXT    NOT NULL,
    ioc_type    TEXT    NOT NULL,
    reputation  TEXT,
    source      TEXT,
    threat_score REAL   DEFAULT 0.0,
    raw_data    TEXT,    -- JSON full response
    cached_at   TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    PRIMARY KEY (indicator, ioc_type)
);
"""


async def init_db() -> None:
    """Create all tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(_CREATE_USERS)
        await db.execute(_CREATE_CASES)
        await db.execute(_CREATE_IOC_CACHE)
        await db.commit()
    logger.info(f"[DB] Initialized SQLite at {DB_PATH}")


# ─── Cases ───────────────────────────────────────────────────────────────────

async def save_case(sha256: str, result: Dict[str, Any], analyst_id: Optional[int] = None) -> None:
    """Persist an analysis result to the cases table."""
    now = datetime.now(timezone.utc).isoformat()
    frs_json = json.dumps(result.get("frs_breakdown", {}))
    scenario_json = json.dumps(result.get("threat_scenario_table", []))
    intel_json = json.dumps(result.get("intelligence_report") or {})

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO cases
              (sha256, package_name, app_name, analysis_mode, family_classification,
               final_risk_score, risk_band, confidence, dynamic_available,
               obfuscation_score, has_reflection, frs_breakdown,
               threat_scenario_table, intelligence_report, analyst_id, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                sha256,
                result.get("package_name"),
                result.get("app_name"),
                result.get("analysis_mode"),
                result.get("family_classification"),
                result.get("final_risk_score"),
                result.get("risk_band"),
                result.get("confidence"),
                1 if result.get("dynamic_available") else 0,
                result.get("obfuscation_score", 0.0),
                1 if result.get("has_reflection") else 0,
                frs_json,
                scenario_json,
                intel_json,
                analyst_id,
                now,
            ),
        )
        await db.commit()
    logger.info(f"[DB] Case saved: {sha256[:12]}… family={result.get('family_classification')}")


async def get_case(sha256: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single case by SHA256."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM cases WHERE sha256 = ?", (sha256,)) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    return _row_to_case(dict(row))


async def list_cases(limit: int = 50, offset: int = 0, analyst_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return paginated list of cases, newest first."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if analyst_id:
            sql = "SELECT * FROM cases WHERE analyst_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params = (analyst_id, limit, offset)
        else:
            sql = "SELECT * FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params = (limit, offset)
        async with db.execute(sql, params) as cur:
            rows = await cur.fetchall()
    return [_row_to_case(dict(r)) for r in rows]


async def count_cases() -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM cases") as cur:
            row = await cur.fetchone()
    return row[0] if row else 0


def _row_to_case(row: Dict) -> Dict[str, Any]:
    """Deserialize JSON fields from SQLite row."""
    for field in ("frs_breakdown", "threat_scenario_table", "intelligence_report"):
        if row.get(field):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                row[field] = {}
    row["dynamic_available"] = bool(row.get("dynamic_available"))
    row["has_reflection"] = bool(row.get("has_reflection"))
    return row


# ─── IOC Cache ────────────────────────────────────────────────────────────────

async def get_cached_ioc(indicator: str, ioc_type: str) -> Optional[Dict[str, Any]]:
    """Return cached IOC reputation if not expired."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM ioc_cache WHERE indicator=? AND ioc_type=? AND expires_at>?",
            (indicator, ioc_type, now),
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("raw_data"):
        try:
            d["raw_data"] = json.loads(d["raw_data"])
        except Exception:
            pass
    return d


async def save_ioc_cache(
    indicator: str,
    ioc_type: str,
    reputation: str,
    source: str,
    threat_score: float,
    raw_data: Dict,
    ttl_hours: int = 24,
) -> None:
    """Cache an IOC reputation result."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(hours=ttl_hours)).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO ioc_cache
              (indicator, ioc_type, reputation, source, threat_score, raw_data, cached_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (indicator, ioc_type, reputation, source, threat_score,
             json.dumps(raw_data), now.isoformat(), expires),
        )
        await db.commit()


# ─── Users ────────────────────────────────────────────────────────────────────

async def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE username=?", (username,)) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE id=?", (user_id,)) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def create_user(username: str, hashed_pw: str, role: str = "analyst") -> int:
    """Insert a new user, return the new row id."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO users (username, hashed_pw, role, created_at) VALUES (?,?,?,?)",
            (username, hashed_pw, role, now),
        )
        await db.commit()
        return cur.lastrowid


async def username_exists(username: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT id FROM users WHERE username=?", (username,)) as cur:
            return await cur.fetchone() is not None
