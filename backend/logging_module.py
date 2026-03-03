"""
logging_module.py
Handles all SQLite persistence for NMIDS.
- Appends packet records to traffic_log
- Appends alert records to alerts
- Reads data for export and statistics
- Manages baseline table during Learning Mode
"""

import sqlite3
import os
import threading
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'nmids.db')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'schema.sql')

_db_lock = threading.Lock()


def _get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialise the database from schema.sql if not already created."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _db_lock:
        conn = _get_conn()
        with open(SCHEMA_PATH, 'r') as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()


# ─── Traffic Log ──────────────────────────────────────────────────────────────

def log_packet(packet: dict):
    """Insert a single packet dict into traffic_log."""
    sql = """
        INSERT INTO traffic_log
            (timestamp, src_ip, dst_ip, protocol, packet_size, port, flags, is_anomaly, anomaly_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    with _db_lock:
        conn = _get_conn()
        conn.execute(sql, (
            packet.get('timestamp', datetime.now().isoformat(timespec='seconds')),
            packet['src_ip'],
            packet['dst_ip'],
            packet['protocol'],
            packet['packet_size'],
            packet['port'],
            packet.get('flags', ''),
            1 if packet.get('is_anomaly') else 0,
            packet.get('anomaly_type', '')
        ))
        conn.commit()
        conn.close()


def get_recent_traffic(limit=100):
    """Return the most recent N traffic_log rows as dicts."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM traffic_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def get_traffic_stats():
    """Return aggregate statistics from traffic_log."""
    with _db_lock:
        conn = _get_conn()
        stats = conn.execute("""
            SELECT
                COUNT(*)                          AS total_packets,
                SUM(is_anomaly)                   AS anomaly_count,
                COUNT(DISTINCT protocol)           AS protocol_count,
                AVG(packet_size)                  AS avg_packet_size
            FROM traffic_log
        """).fetchone()
        conn.close()
    return dict(stats) if stats else {}


def get_traffic_volume_over_time(minutes=30):
    """Return per-minute packet counts for the last N minutes."""
    cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat(timespec='seconds')
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute("""
            SELECT
                strftime('%H:%M', timestamp) AS minute,
                COUNT(*)                     AS count,
                SUM(is_anomaly)              AS anomalies
            FROM traffic_log
            WHERE timestamp >= ?
            GROUP BY minute
            ORDER BY minute
        """, (cutoff,)).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def get_protocol_distribution():
    """Return packet counts grouped by protocol."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute("""
            SELECT protocol, COUNT(*) AS count
            FROM traffic_log
            GROUP BY protocol
            ORDER BY count DESC
        """).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def get_packet_size_histogram():
    """Return packet size distribution in buckets."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute("""
            SELECT
                CASE
                    WHEN packet_size <  100  THEN '0-99'
                    WHEN packet_size <  300  THEN '100-299'
                    WHEN packet_size <  600  THEN '300-599'
                    WHEN packet_size < 1000  THEN '600-999'
                    WHEN packet_size < 1400  THEN '1000-1399'
                    ELSE '1400+'
                END AS bucket,
                COUNT(*) AS count
            FROM traffic_log
            GROUP BY bucket
            ORDER BY MIN(packet_size)
        """).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def export_traffic_records(limit=1000):
    """Return up to limit traffic_log rows for export."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM traffic_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


# ─── Alerts ───────────────────────────────────────────────────────────────────

def log_alert(alert: dict):
    """Insert a single alert dict into the alerts table."""
    sql = """
        INSERT INTO alerts
            (timestamp, alert_type, severity, src_ip, dst_ip, description, acknowledged)
        VALUES (?, ?, ?, ?, ?, ?, 0)
    """
    with _db_lock:
        conn = _get_conn()
        cur = conn.execute(sql, (
            alert.get('timestamp', datetime.now().isoformat(timespec='seconds')),
            alert['alert_type'],
            alert['severity'],
            alert['src_ip'],
            alert['dst_ip'],
            alert['description']
        ))
        alert_id = cur.lastrowid
        conn.commit()
        conn.close()
    return alert_id


def get_alerts(limit=200, unacked_only=False):
    """Return recent alerts, optionally filtered to unacknowledged only."""
    where = "WHERE acknowledged = 0" if unacked_only else ""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id: int):
    """Mark a single alert as acknowledged."""
    with _db_lock:
        conn = _get_conn()
        conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        conn.commit()
        conn.close()


def acknowledge_all_alerts():
    """Mark all alerts as acknowledged."""
    with _db_lock:
        conn = _get_conn()
        conn.execute("UPDATE alerts SET acknowledged = 1")
        conn.commit()
        conn.close()


def clear_all_alerts():
    """Permanently delete all alert records."""
    with _db_lock:
        conn = _get_conn()
        conn.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()


def get_alert_stats():
    """Return alert counts by severity and acknowledgement status."""
    with _db_lock:
        conn = _get_conn()
        by_severity = conn.execute("""
            SELECT severity, COUNT(*) AS count
            FROM alerts
            GROUP BY severity
        """).fetchall()
        by_type = conn.execute("""
            SELECT alert_type, COUNT(*) AS count
            FROM alerts
            GROUP BY alert_type
            ORDER BY count DESC
        """).fetchall()
        totals = conn.execute("""
            SELECT
                COUNT(*)                     AS total,
                SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END) AS active
            FROM alerts
        """).fetchone()
        conn.close()
    return {
        'by_severity': [dict(r) for r in by_severity],
        'by_type':     [dict(r) for r in by_type],
        'total':       totals['total']  if totals else 0,
        'active':      totals['active'] if totals else 0,
    }


def get_alerts_over_time(minutes=30):
    """Return per-minute alert counts for the last N minutes."""
    cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat(timespec='seconds')
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute("""
            SELECT
                strftime('%H:%M', timestamp) AS minute,
                COUNT(*) AS count
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY minute
            ORDER BY minute
        """, (cutoff,)).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def export_alert_records(limit=500):
    """Return up to limit alert rows for export."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


# ─── Baseline ─────────────────────────────────────────────────────────────────

def upsert_baseline(protocol: str, avg_size: float, avg_rate: float, sample_count: int):
    """Insert or update a baseline record for a protocol."""
    sql = """
        INSERT INTO baseline (protocol, avg_size, avg_rate, sample_count, updated_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        ON CONFLICT(protocol) DO UPDATE SET
            avg_size     = excluded.avg_size,
            avg_rate     = excluded.avg_rate,
            sample_count = excluded.sample_count,
            updated_at   = excluded.updated_at
    """
    with _db_lock:
        conn = _get_conn()
        conn.execute(sql, (protocol, avg_size, avg_rate, sample_count))
        conn.commit()
        conn.close()


def get_baselines():
    """Return all baseline records."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute("SELECT * FROM baseline ORDER BY protocol").fetchall()
        conn.close()
    return [dict(r) for r in rows]


# ─── Maintenance ──────────────────────────────────────────────────────────────

def purge_old_traffic(days: int):
    """Delete traffic_log entries older than N days."""
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec='seconds')
    with _db_lock:
        conn = _get_conn()
        cur = conn.execute("DELETE FROM traffic_log WHERE timestamp < ?", (cutoff,))
        deleted = cur.rowcount
        conn.commit()
        conn.close()
    return deleted


def vacuum_db():
    """Run VACUUM to reclaim SQLite storage."""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("VACUUM")
        conn.close()
