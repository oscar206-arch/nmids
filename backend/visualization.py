"""
visualization.py
Aggregates and formats data for all 8 Chart.js dashboard chart endpoints.
All methods return dicts ready for JSON serialisation.
"""

import backend.logging_module as db

SEVERITY_COLOURS = {
    "LOW":      "#00d4ff",
    "MEDIUM":   "#f39c12",
    "HIGH":     "#e74c3c",
    "CRITICAL": "#ff0040",
}

PROTOCOL_COLOURS = [
    "#00d4ff", "#7b2ff7", "#f39c12", "#2ecc71",
    "#e74c3c", "#9b59b6", "#1abc9c", "#e67e22",
    "#3498db", "#ff0040"
]


def traffic_volume_chart(minutes=30) -> dict:
    """Line chart: packets per minute + anomalies per minute."""
    rows = db.get_traffic_volume_over_time(minutes)
    return {
        "labels":   [r['minute'] for r in rows],
        "datasets": [
            {
                "label":           "Total Packets",
                "data":            [r['count'] for r in rows],
                "borderColor":     "#00d4ff",
                "backgroundColor": "rgba(0,212,255,0.1)",
                "tension":         0.4,
                "fill":            True,
            },
            {
                "label":           "Anomalies",
                "data":            [r['anomalies'] for r in rows],
                "borderColor":     "#ff0040",
                "backgroundColor": "rgba(255,0,64,0.1)",
                "tension":         0.4,
                "fill":            True,
            }
        ]
    }


def protocol_distribution_chart() -> dict:
    """Doughnut chart: packets per protocol."""
    rows   = db.get_protocol_distribution()
    labels = [r['protocol'] for r in rows]
    data   = [r['count']    for r in rows]
    return {
        "labels":   labels,
        "datasets": [{
            "data":            data,
            "backgroundColor": PROTOCOL_COLOURS[:len(labels)],
            "borderColor":     "#0a0a1a",
            "borderWidth":     2,
        }]
    }


def alert_severity_chart() -> dict:
    """Bar chart: alert count per severity."""
    stats  = db.get_alert_stats()
    rows   = stats.get('by_severity', [])
    order  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    counts = {r['severity']: r['count'] for r in rows}
    return {
        "labels":   order,
        "datasets": [{
            "label":           "Alerts",
            "data":            [counts.get(s, 0) for s in order],
            "backgroundColor": [SEVERITY_COLOURS[s] for s in order],
            "borderRadius":    4,
        }]
    }


def alert_type_chart() -> dict:
    """Horizontal bar chart: alert count per alert_type."""
    stats  = db.get_alert_stats()
    rows   = stats.get('by_type', [])[:8]   # top 8
    return {
        "labels":   [r['alert_type'].replace('_', ' ').title() for r in rows],
        "datasets": [{
            "label":           "Count",
            "data":            [r['count'] for r in rows],
            "backgroundColor": "#7b2ff7",
            "borderRadius":    4,
        }]
    }


def packet_size_histogram() -> dict:
    """Bar chart: packet counts by size bucket."""
    rows = db.get_packet_size_histogram()
    return {
        "labels":   [r['bucket'] + ' B' for r in rows],
        "datasets": [{
            "label":           "Packets",
            "data":            [r['count'] for r in rows],
            "backgroundColor": "#2ecc71",
            "borderRadius":    4,
        }]
    }


def anomalies_over_time_chart(minutes=30) -> dict:
    """Line chart: anomalies per minute."""
    rows = db.get_alerts_over_time(minutes)
    return {
        "labels":   [r['minute'] for r in rows],
        "datasets": [{
            "label":           "Alerts",
            "data":            [r['count'] for r in rows],
            "borderColor":     "#f39c12",
            "backgroundColor": "rgba(243,156,18,0.15)",
            "tension":         0.4,
            "fill":            True,
        }]
    }


def summary_stats() -> dict:
    """Returns the four live stat cards on the Dashboard home page."""
    t = db.get_traffic_stats()
    a = db.get_alert_stats()
    return {
        "total_packets":  t.get('total_packets', 0) or 0,
        "anomaly_count":  t.get('anomaly_count', 0)  or 0,
        "active_alerts":  a.get('active', 0),
        "total_alerts":   a.get('total', 0),
        "avg_packet_size": round(t.get('avg_packet_size', 0) or 0, 1),
    }
