-- NMIDS SQLite Schema
-- traffic_log: append-only packet store
CREATE TABLE IF NOT EXISTS traffic_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL DEFAULT (datetime('now')),
    src_ip       TEXT    NOT NULL,
    dst_ip       TEXT    NOT NULL,
    protocol     TEXT    NOT NULL,
    packet_size  INTEGER NOT NULL,
    port         INTEGER NOT NULL,
    flags        TEXT    NOT NULL DEFAULT '',
    is_anomaly   INTEGER NOT NULL DEFAULT 0,  -- 0=normal, 1=anomaly
    anomaly_type TEXT    NOT NULL DEFAULT ''
);

-- alerts: intrusion events raised by detection engine
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL DEFAULT (datetime('now')),
    alert_type   TEXT    NOT NULL,
    severity     TEXT    NOT NULL,  -- LOW | MEDIUM | HIGH | CRITICAL
    src_ip       TEXT    NOT NULL,
    dst_ip       TEXT    NOT NULL,
    description  TEXT    NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0   -- 0=unacked, 1=acked
);

-- baseline: protocol averages collected during Learning Mode
CREATE TABLE IF NOT EXISTS baseline (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol     TEXT    NOT NULL UNIQUE,
    avg_size     REAL    NOT NULL DEFAULT 0.0,
    avg_rate     REAL    NOT NULL DEFAULT 0.0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp  ON traffic_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_src_ip     ON traffic_log(src_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_is_anomaly ON traffic_log(is_anomaly);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp   ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_acked       ON alerts(acknowledged);
