# NMIDS — Network Monitoring and Intrusion Detection System

A self-contained Python/Flask application that simulates network traffic,
detects intrusion patterns using 8 stateful rules, and provides a real-time
web dashboard — no raw sockets, Scapy, or root privileges required.

---

## Quick Start

```bash
# 1. Install the only dependency
pip install flask

# 2. Run the application
python dashboard.py

# 3. Open in browser
http://localhost:5000
```

---

## Project Structure

```
nmids/
├── dashboard.py                  ← Flask entry point (run this)
├── requirements.txt
│
├── backend/
│   ├── __init__.py
│   ├── traffic_generator.py      ← 11 attack scenario simulators
│   ├── detection_engine.py       ← 8 stateful detection rules
│   ├── alert_module.py           ← SSE alert dispatcher
│   ├── logging_module.py         ← SQLite persistence layer
│   ├── visualization.py          ← Chart.js data aggregators
│   └── db_inspector.py           ← Schema browser & SQL console
│
├── frontend/
│   ├── templates/
│   │   ├── base.html             ← Sidebar navigation layout
│   │   ├── dashboard.html        ← Home: stats, charts, live feed
│   │   ├── alerts.html           ← Alert management & SSE toasts
│   │   ├── simulate.html         ← Scenario selector & controls
│   │   ├── learning.html         ← Learning mode & baselines
│   │   ├── database.html         ← DB inspector & SQL console
│   │   └── export.html           ← JSON/CSV download
│   └── static/
│       └── css/style.css         ← Dark cyber-terminal theme
│
└── database/
    ├── schema.sql                ← Table definitions & indexes
    └── nmids.db                  ← SQLite database (auto-created)
```

---

## Dashboard Pages

| Page       | URL          | Description |
|------------|--------------|-------------|
| Dashboard  | `/`          | Live stat cards, 5 charts, live packet feed |
| Alerts     | `/alerts`    | SSE real-time alerts, ack/clear, severity filter |
| Simulate   | `/simulate`  | 11 scenario cards, rate slider, start/stop |
| Learning   | `/learning`  | Baseline profiling mode |
| Database   | `/database`  | Schema browser, row pager, read-only SQL console |
| Export     | `/export`    | JSON (Elasticsearch/Splunk) and CSV (pandas/Excel) |

---

## Detection Rules

| # | Rule              | Trigger                                      | Severity |
|---|-------------------|----------------------------------------------|----------|
| 1 | Port Scan         | >15 unique ports probed from 1 IP in 10s     | HIGH |
| 2 | Traffic Flood     | >100 packets from 1 IP in 5s                 | CRITICAL |
| 3 | SYN Flood         | >20 TCP SYN to 1 dst in 10s                  | CRITICAL |
| 4 | Brute Force       | >20 auth-port connections from 1 IP in 10s   | HIGH |
| 5 | Oversized Packet  | Any packet > 1400 bytes                       | MEDIUM |
| 6 | Suspicious Port   | Connection to known C2/malware port           | MEDIUM |
| 7 | ARP Spoofing      | Any ARP protocol packet                       | HIGH |
| 8 | DNS Tunnelling    | DNS packet > 150 bytes                        | HIGH |

---

## Simulation Scenarios

`normal`, `port_scan`, `ddos`, `brute_force`, `syn_flood`,
`suspicious_port`, `large_packet`, `icmp_flood`, `arp_spoofing`,
`dns_tunnel`, `mixed`

---

## Database Tables

| Table        | Description |
|--------------|-------------|
| `traffic_log`| Every simulated packet (append-only) |
| `alerts`     | Detected intrusion events (`acknowledged` is only mutable field) |
| `baseline`   | Protocol averages collected during Learning Mode |

---

## API Reference

```
GET  /api/stats                     # Summary stats (4 counters)
GET  /api/charts/<name>             # Chart.js dataset
GET  /api/alerts                    # Recent alerts
POST /api/alerts/acknowledge/<id>   # Ack one alert
POST /api/alerts/acknowledge_all    # Ack all
POST /api/alerts/clear              # Delete all alerts
GET  /api/stream                    # SSE alert stream
GET  /api/packet_stream             # SSE live packet feed
POST /api/simulate/start            # {scenario, rate}
POST /api/simulate/stop
GET  /api/simulate/status
POST /api/learning/start
POST /api/learning/stop
GET  /api/db/schema
GET  /api/db/tables/<table>         # Paginated rows
POST /api/db/query                  # {sql} - SELECT only
GET  /api/export/json               # nmids_export.json
GET  /api/export/csv                # nmids_traffic.csv
```

---

## Requirements

- Python 3.8+
- Flask (`pip install flask`)
- No root privileges, no live network interface, no Scapy required
- Internet access only needed to load Chart.js from CDN on first load
