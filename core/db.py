"""
HIDS Database Layer — SQLite, no external dependencies.
Stores all alerts, sessions, and stats persistently.
"""
import sqlite3, os, json
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.environ.get("HIDS_DB", "/var/lib/hids/hids.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    threat        TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    confidence    REAL    NOT NULL,
    mitre_id      TEXT,
    mitre_name    TEXT,
    features      TEXT,   -- JSON
    suppressed    INTEGER DEFAULT 0,
    session_id    TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT    PRIMARY KEY,
    started_at    TEXT    NOT NULL,
    ended_at      TEXT,
    total_scans   INTEGER DEFAULT 0,
    total_alerts  INTEGER DEFAULT 0,
    suppressed    INTEGER DEFAULT 0,
    syscalls      INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS stats_hourly (
    hour          TEXT    PRIMARY KEY,  -- ISO hour: 2025-03-08T14
    alert_count   INTEGER DEFAULT 0,
    scan_count    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_threat   ON alerts(threat);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
"""

def ensure_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)

@contextmanager
def db():
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

# ── Writes ────────────────────────────────────────────────────────────────────
def insert_alert(alert: dict):
    with db() as conn:
        conn.execute("""
            INSERT INTO alerts
              (timestamp,threat,severity,confidence,mitre_id,mitre_name,features,suppressed,session_id)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            alert.get("timestamp", datetime.now().isoformat()),
            alert.get("threat","ANOMALOUS BEHAVIOUR"),
            alert.get("severity","LOW"),
            alert.get("confidence", 0.0),
            alert.get("mitre_id",""),
            alert.get("mitre_name",""),
            json.dumps(alert.get("features",{})),
            1 if alert.get("suppressed") else 0,
            alert.get("session_id",""),
        ))
        # Update hourly stats
        hour = alert.get("timestamp","")[:13]
        conn.execute("""
            INSERT INTO stats_hourly(hour,alert_count,scan_count)
            VALUES(?,1,0)
            ON CONFLICT(hour) DO UPDATE SET alert_count=alert_count+1
        """, (hour,))

def upsert_session(session: dict):
    with db() as conn:
        conn.execute("""
            INSERT INTO sessions(id,started_at,ended_at,total_scans,total_alerts,suppressed,syscalls)
            VALUES(:id,:started_at,:ended_at,:total_scans,:total_alerts,:suppressed,:syscalls)
            ON CONFLICT(id) DO UPDATE SET
              ended_at=:ended_at, total_scans=:total_scans,
              total_alerts=:total_alerts, suppressed=:suppressed, syscalls=:syscalls
        """, session)

def tick_scan(hour: str):
    with db() as conn:
        conn.execute("""
            INSERT INTO stats_hourly(hour,alert_count,scan_count)
            VALUES(?,0,1)
            ON CONFLICT(hour) DO UPDATE SET scan_count=scan_count+1
        """, (hour,))

# ── Reads ─────────────────────────────────────────────────────────────────────
def get_recent_alerts(limit=200, suppressed=None):
    with db() as conn:
        if suppressed is None:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE suppressed=? ORDER BY id DESC LIMIT ?",
                (1 if suppressed else 0, limit)
            ).fetchall()
    return [dict(r) for r in rows]

def get_threat_breakdown():
    with db() as conn:
        rows = conn.execute("""
            SELECT threat, COUNT(*) as count,
                   AVG(confidence) as avg_conf,
                   MAX(timestamp) as last_seen
            FROM alerts WHERE suppressed=0
            GROUP BY threat ORDER BY count DESC
        """).fetchall()
    return [dict(r) for r in rows]

def get_severity_counts():
    with db() as conn:
        rows = conn.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts WHERE suppressed=0
            GROUP BY severity
        """).fetchall()
    return {r["severity"]: r["count"] for r in rows}

def get_hourly_stats(hours=48):
    with db() as conn:
        rows = conn.execute("""
            SELECT hour, alert_count, scan_count
            FROM stats_hourly
            ORDER BY hour DESC LIMIT ?
        """, (hours,)).fetchall()
    return [dict(r) for r in rows]

def get_daily_heatmap(days=30):
    """Returns counts per day for heatmap."""
    with db() as conn:
        rows = conn.execute("""
            SELECT substr(timestamp,1,10) as day, COUNT(*) as count
            FROM alerts WHERE suppressed=0
            GROUP BY day ORDER BY day
        """).fetchall()
    return [dict(r) for r in rows]

def get_sessions(limit=20):
    with db() as conn:
        rows = conn.execute("""
            SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]

def get_summary():
    with db() as conn:
        total     = conn.execute("SELECT COUNT(*) FROM alerts WHERE suppressed=0").fetchone()[0]
        sup       = conn.execute("SELECT COUNT(*) FROM alerts WHERE suppressed=1").fetchone()[0]
        sessions  = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        today     = datetime.now().strftime("%Y-%m-%d")
        today_ct  = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE suppressed=0 AND timestamp LIKE ?",
            (today+"%",)
        ).fetchone()[0]
        last_alert= conn.execute(
            "SELECT timestamp,threat,severity FROM alerts WHERE suppressed=0 ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return {
        "total_alerts": total,
        "suppressed":   sup,
        "sessions":     sessions,
        "today":        today_ct,
        "last_alert":   dict(last_alert) if last_alert else None,
    }
