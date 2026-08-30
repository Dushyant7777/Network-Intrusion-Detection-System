"""
database.py
------------
SQLite persistence layer for the NIDS.

Two tables:
  - packets: a capped, rolling log of captured/simulated packet metadata
             (used for the "recent traffic" view and evidence trail)
  - alerts:  every detected incident, kept permanently for investigation
             and reporting (severity, type, source/destination, details)

Each function opens a short-lived connection rather than sharing one
across threads. At this scale (an educational NIDS, not an enterprise
SIEM) that is simpler and safer than manual thread-safe connection
pooling, and WAL mode keeps reads from blocking on writes.
"""

import sqlite3
import time
import json
import threading

_init_lock = threading.Lock()


def get_connection(db_path):
    """Return a new SQLite connection configured for concurrent access."""
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db(db_path):
    """Create tables/indices if they don't already exist. Safe to call repeatedly."""
    with _init_lock:
        conn = get_connection(db_path)
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    size INTEGER,
                    flags TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    description TEXT,
                    details TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.commit()

            # Migration for databases created before roles existed: CREATE
            # TABLE IF NOT EXISTS above won't retrofit a column onto an
            # already-existing users table, so add it explicitly here. A
            # no-op (raises, caught, ignored) on any database that already
            # has the column -- which includes every fresh install, since
            # the CREATE TABLE above already included it.
            try:
                conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
                conn.commit()
            except sqlite3.OperationalError:
                pass
        finally:
            conn.close()


# ---------------------------------------------------------------- packets --

def insert_packets_batch(conn, packets):
    """Bulk-insert packet metadata dicts in a single transaction."""
    if not packets:
        return
    conn.executemany(
        """
        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, flags)
        VALUES (:timestamp, :src_ip, :dst_ip, :protocol, :src_port, :dst_port, :size, :flags)
        """,
        packets,
    )
    conn.commit()


def prune_old_packets(conn, keep_last=5000):
    """Cap the packets table so the demo DB doesn't grow without bound."""
    conn.execute(
        """
        DELETE FROM packets
        WHERE id NOT IN (SELECT id FROM packets ORDER BY id DESC LIMIT ?)
        """,
        (keep_last,),
    )
    conn.commit()


def get_recent_packets(conn, limit=100):
    rows = conn.execute(
        "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_total_packet_count(conn):
    row = conn.execute("SELECT COUNT(*) AS c FROM packets").fetchone()
    return row["c"] if row else 0


# ----------------------------------------------------------------- alerts --

def insert_alert(conn, alert):
    """Insert a single alert (low frequency relative to packets, so no batching)."""
    cur = conn.execute(
        """
        INSERT INTO alerts (timestamp, alert_type, severity, src_ip, dst_ip, description, details)
        VALUES (:timestamp, :alert_type, :severity, :src_ip, :dst_ip, :description, :details)
        """,
        {
            "timestamp": alert["timestamp"],
            "alert_type": alert["alert_type"],
            "severity": alert["severity"],
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
            "description": alert.get("description", ""),
            "details": json.dumps(alert.get("details", {})),
        },
    )
    conn.commit()
    return cur.lastrowid


def get_recent_alerts(conn, limit=50, severity=None, alert_type=None):
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if alert_type:
        query += " AND alert_type = ?"
        params.append(alert_type)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d["details"]) if d["details"] else {}
        except (TypeError, json.JSONDecodeError):
            d["details"] = {}
        out.append(d)
    return out


def get_alert_counts_by_severity(conn):
    rows = conn.execute(
        "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
    ).fetchall()
    return {r["severity"]: r["c"] for r in rows}


def get_alerts_by_day(conn, days=14):
    """Alert counts grouped by calendar day, for the historical trend chart."""
    cutoff = time.time() - days * 86400
    rows = conn.execute(
        """
        SELECT date(timestamp, 'unixepoch') AS day, COUNT(*) AS c
        FROM alerts
        WHERE timestamp >= ?
        GROUP BY day
        ORDER BY day ASC
        """,
        (cutoff,),
    ).fetchall()
    return [{"day": r["day"], "count": r["c"]} for r in rows]


def get_alerts_by_type(conn):
    rows = conn.execute(
        "SELECT alert_type, COUNT(*) AS c FROM alerts GROUP BY alert_type ORDER BY c DESC"
    ).fetchall()
    return [{"alert_type": r["alert_type"], "count": r["c"]} for r in rows]


def get_top_alert_sources(conn, limit=10):
    rows = conn.execute(
        """
        SELECT src_ip, COUNT(*) AS c
        FROM alerts
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY c DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [{"src_ip": r["src_ip"], "count": r["c"]} for r in rows]


def clear_all_data(conn):
    """Wipe packets and alerts (used by the 'reset demo data' admin action)."""
    conn.execute("DELETE FROM packets")
    conn.execute("DELETE FROM alerts")
    conn.commit()
