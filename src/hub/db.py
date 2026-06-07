import sqlite3
import json
import os
import logging
from contextlib import contextmanager
from datetime import datetime
from typing import List, Optional, Any, Dict

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("MFS_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "data", "hub.db"))


def get_db_path() -> str:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return DB_PATH


@contextmanager
def get_conn():
    conn = sqlite3.connect(get_db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                user_name TEXT DEFAULT '',
                os TEXT DEFAULT '',
                ip TEXT DEFAULT '',
                last_heartbeat TEXT,
                license_status TEXT DEFAULT 'active',
                license_expiry TEXT DEFAULT '2027-12-31',
                alert_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'healthy',
                logs TEXT DEFAULT '[]',
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                severity TEXT DEFAULT 'MED',
                type TEXT,
                source TEXT,
                source_type TEXT DEFAULT 'endpoint',
                description TEXT,
                status TEXT DEFAULT 'open',
                assignee TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS vault_entries (
                id TEXT PRIMARY KEY,
                agent_id TEXT,
                hostname TEXT,
                timestamp TEXT,
                duration TEXT DEFAULT '00:05:00',
                size_bytes INTEGER DEFAULT 0,
                hash TEXT,
                status TEXT DEFAULT 'sealed'
            );

            CREATE TABLE IF NOT EXISTS traffic_entries (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                endpoint TEXT,
                user_name TEXT,
                method TEXT DEFAULT 'GET',
                domain TEXT,
                path TEXT DEFAULT '/',
                category TEXT DEFAULT 'UNCATEGORIZED',
                status TEXT DEFAULT 'ALLOWED',
                size_kb REAL DEFAULT 0,
                ssl INTEGER DEFAULT 0,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS dlp_alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                endpoint TEXT,
                user_name TEXT,
                type TEXT DEFAULT 'USB',
                destination TEXT,
                size_kb REAL DEFAULT 0,
                status TEXT DEFAULT 'FLAGGED',
                detail TEXT
            );

            CREATE TABLE IF NOT EXISTS user_risk (
                id TEXT PRIMARY KEY,
                username TEXT,
                display_name TEXT,
                department TEXT DEFAULT 'IT',
                role TEXT DEFAULT 'User',
                score INTEGER DEFAULT 0,
                level TEXT DEFAULT 'NORMAL',
                trend TEXT DEFAULT 'STABLE',
                trend_delta INTEGER DEFAULT 0,
                last_active TEXT,
                alert_count INTEGER DEFAULT 0,
                keyword_count INTEGER DEFAULT 0,
                bulk_count INTEGER DEFAULT 0,
                after_hours_count INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                linked_incidents TEXT DEFAULT '[]',
                vault_recordings INTEGER DEFAULT 0,
                recommendation TEXT DEFAULT 'No action required.',
                recommendation_level TEXT DEFAULT 'CLEAR',
                recent_events TEXT DEFAULT '[]',
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT DEFAULT (datetime('now'))
            );
        """)
    logger.info("Database initialised at %s", get_db_path())


# ── Agents ────────────────────────────────────────────────────────────────────

def upsert_agent(data: Dict[str, Any]):
    now = datetime.utcnow().isoformat()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO agents (id, hostname, user_name, os, ip, last_heartbeat,
                license_status, license_expiry, alert_count, status, logs, updated_at)
            VALUES (:id, :hostname, :user_name, :os, :ip, :last_heartbeat,
                :license_status, :license_expiry, :alert_count, :status, :logs, :now)
            ON CONFLICT(id) DO UPDATE SET
                hostname=excluded.hostname, user_name=excluded.user_name,
                os=excluded.os, ip=excluded.ip, last_heartbeat=excluded.last_heartbeat,
                alert_count=excluded.alert_count, status=excluded.status,
                logs=excluded.logs, updated_at=excluded.updated_at
        """, {**data, "now": now})


def get_agents() -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY hostname").fetchall()
    return [dict(r) for r in rows]


# ── Alerts ────────────────────────────────────────────────────────────────────

def insert_alert(data: Dict[str, Any]):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO alerts (id, timestamp, severity, type, source,
                source_type, description, status, assignee)
            VALUES (:id, :timestamp, :severity, :type, :source,
                :source_type, :description, :status, :assignee)
        """, data)


def get_alerts(limit: int = 100) -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def update_alert_status(alert_id: str, status: str, assignee: Optional[str] = None):
    with get_conn() as conn:
        conn.execute(
            "UPDATE alerts SET status=?, assignee=? WHERE id=?",
            (status, assignee, alert_id)
        )


# ── Vault ─────────────────────────────────────────────────────────────────────

def insert_vault_entry(data: Dict[str, Any]):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO vault_entries
                (id, agent_id, hostname, timestamp, duration, size_bytes, hash, status)
            VALUES (:id, :agent_id, :hostname, :timestamp, :duration, :size_bytes, :hash, :status)
        """, data)


def get_vault_entries(limit: int = 50) -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM vault_entries ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_vault_size_gb() -> float:
    with get_conn() as conn:
        row = conn.execute("SELECT SUM(size_bytes) as total FROM vault_entries").fetchone()
    total = row["total"] or 0
    return round(total / (1024 ** 3), 2)


# ── Traffic ───────────────────────────────────────────────────────────────────

def insert_traffic(data: Dict[str, Any]):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO traffic_entries
                (id, timestamp, endpoint, user_name, method, domain, path,
                 category, status, size_kb, ssl, reason)
            VALUES (:id, :timestamp, :endpoint, :user_name, :method, :domain, :path,
                    :category, :status, :size_kb, :ssl, :reason)
        """, data)


def get_traffic(limit: int = 50) -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM traffic_entries ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── DLP ───────────────────────────────────────────────────────────────────────

def insert_dlp(data: Dict[str, Any]):
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO dlp_alerts
                (id, timestamp, endpoint, user_name, type, destination, size_kb, status, detail)
            VALUES (:id, :timestamp, :endpoint, :user_name, :type, :destination, :size_kb, :status, :detail)
        """, data)


def get_dlp(limit: int = 20) -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM dlp_alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── User Risk ─────────────────────────────────────────────────────────────────

def upsert_user_risk(data: Dict[str, Any]):
    now = datetime.utcnow().isoformat()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO user_risk (id, username, display_name, department, role,
                score, level, trend, trend_delta, last_active,
                alert_count, keyword_count, bulk_count, after_hours_count, blocked_count,
                linked_incidents, vault_recordings, recommendation, recommendation_level,
                recent_events, updated_at)
            VALUES (:id, :username, :display_name, :department, :role,
                :score, :level, :trend, :trend_delta, :last_active,
                :alert_count, :keyword_count, :bulk_count, :after_hours_count, :blocked_count,
                :linked_incidents, :vault_recordings, :recommendation, :recommendation_level,
                :recent_events, :now)
            ON CONFLICT(id) DO UPDATE SET
                score=excluded.score, level=excluded.level,
                trend=excluded.trend, trend_delta=excluded.trend_delta,
                last_active=excluded.last_active, alert_count=excluded.alert_count,
                bulk_count=excluded.bulk_count, after_hours_count=excluded.after_hours_count,
                blocked_count=excluded.blocked_count,
                linked_incidents=excluded.linked_incidents,
                recommendation=excluded.recommendation,
                recommendation_level=excluded.recommendation_level,
                recent_events=excluded.recent_events, updated_at=excluded.updated_at
        """, {**data, "now": now})


def get_user_risk() -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM user_risk ORDER BY score DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_previous_scores() -> Dict[str, int]:
    """Return {username: score} from last update for trend comparison."""
    with get_conn() as conn:
        rows = conn.execute("SELECT username, score FROM user_risk").fetchall()
    return {r["username"]: r["score"] for r in rows}


# ── Config ────────────────────────────────────────────────────────────────────

def get_config(key: str) -> Optional[str]:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_config(key: str, value: str):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO config (key, value, updated_at) VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """, (key, value))
