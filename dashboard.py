"""
dashboard.py
Flask application entry point.
Routes:
  GET  /                         → Dashboard home
  GET  /alerts                   → Alerts page
  GET  /simulate                 → Simulate page
  GET  /learning                 → Learning Mode page
  GET  /database                 → DB Inspector page
  GET  /export                   → Export page

API:
  GET  /api/stats                → JSON summary stats
  GET  /api/charts/<name>        → JSON Chart.js dataset
  GET  /api/alerts               → JSON recent alerts
  POST /api/alerts/acknowledge/<id>
  POST /api/alerts/acknowledge_all
  POST /api/alerts/clear
  GET  /api/stream               → SSE alert stream
  GET  /api/packet_stream        → SSE live packet feed

  POST /api/simulate/start       → {scenario, rate}
  POST /api/simulate/stop
  POST /api/simulate/update      → {scenario?, rate?}
  GET  /api/simulate/status

  POST /api/learning/start
  POST /api/learning/stop
  GET  /api/learning/baseline

  GET  /api/db/schema
  GET  /api/db/tables/<table>    → paginated rows
  POST /api/db/query             → {sql}
  GET  /api/db/counts
  POST /api/db/vacuum
  POST /api/db/purge             → {days}

  GET  /api/export/json
  GET  /api/export/csv
"""

import csv
import io
import json
import os

from flask import (Flask, Response, jsonify, render_template,
                   request, stream_with_context)

import backend.logging_module as db
import backend.db_inspector   as inspector
import backend.visualization  as viz
from backend.alert_module     import AlertModule, PacketFeed
from backend.detection_engine import DetectionEngine
from backend.traffic_generator import TrafficGenerator, SCENARIO_DESCRIPTIONS

# ─── Application setup ────────────────────────────────────────────────────────

BASE_DIR     = os.path.dirname(__file__)
TEMPLATE_DIR = os.path.join(BASE_DIR, 'frontend', 'templates')
STATIC_DIR   = os.path.join(BASE_DIR, 'frontend', 'static')

app = Flask(__name__,
            template_folder=TEMPLATE_DIR,
            static_folder=STATIC_DIR)
app.config['SECRET_KEY'] = 'nmids-dev-secret'

# ─── Core modules (singletons) ────────────────────────────────────────────────

alert_module = AlertModule()
packet_feed  = PacketFeed()
engine       = DetectionEngine(on_alert=alert_module.dispatch)


def _on_packet(packet: dict):
    """Callback: run detection, log, push to live feed."""
    packet = engine.analyse(packet)
    db.log_packet(packet)
    packet_feed.push(packet)


generator = TrafficGenerator(on_packet=_on_packet)

# ─── Init DB ──────────────────────────────────────────────────────────────────
db.init_db()


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    stats = viz.summary_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/alerts')
def alerts_page():
    return render_template('alerts.html')

@app.route('/simulate')
def simulate_page():
    return render_template('simulate.html',
                           scenarios=SCENARIO_DESCRIPTIONS,
                           is_running=generator.is_running(),
                           current_scenario=generator.scenario,
                           current_rate=generator.rate)

@app.route('/learning')
def learning_page():
    return render_template('learning.html',
                           learning_mode=engine.learning_mode,
                           baselines=db.get_baselines())

@app.route('/database')
def database_page():
    return render_template('database.html',
                           schema=inspector.get_schema(),
                           counts=inspector.get_table_counts())

@app.route('/export')
def export_page():
    return render_template('export.html')


# ═══════════════════════════════════════════════════════════════════════════════
# STATS & CHARTS API
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/stats')
def api_stats():
    return jsonify(viz.summary_stats())

@app.route('/api/charts/<name>')
def api_chart(n):
    minutes = int(request.args.get('minutes', 30))
    charts  = {
        'traffic_volume':    lambda: viz.traffic_volume_chart(minutes),
        'protocol':          viz.protocol_distribution_chart,
        'alert_severity':    viz.alert_severity_chart,
        'alert_type':        viz.alert_type_chart,
        'packet_size':       viz.packet_size_histogram,
        'anomalies_over_time': lambda: viz.anomalies_over_time_chart(minutes),
    }
    fn = charts.get(n)
    if not fn:
        return jsonify({'error': 'Unknown chart'}), 404
    return jsonify(fn())


# ═══════════════════════════════════════════════════════════════════════════════
# ALERTS API
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/alerts')
def api_alerts():
    unacked = request.args.get('unacked', 'false').lower() == 'true'
    limit   = int(request.args.get('limit', 200))
    return jsonify(db.get_alerts(limit=limit, unacked_only=unacked))

@app.route('/api/alerts/acknowledge/<int:alert_id>', methods=['POST'])
def api_ack_alert(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({'ok': True})

@app.route('/api/alerts/acknowledge_all', methods=['POST'])
def api_ack_all():
    db.acknowledge_all_alerts()
    return jsonify({'ok': True})

@app.route('/api/alerts/clear', methods=['POST'])
def api_clear_alerts():
    db.clear_all_alerts()
    return jsonify({'ok': True})


# ═══════════════════════════════════════════════════════════════════════════════
# SSE STREAMS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/stream')
def api_alert_stream():
    return Response(
        stream_with_context(alert_module.event_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':  'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )

@app.route('/api/packet_stream')
def api_packet_stream():
    return Response(
        stream_with_context(packet_feed.event_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':  'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SIMULATION API
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/simulate/start', methods=['POST'])
def api_sim_start():
    data     = request.get_json(silent=True) or {}
    scenario = data.get('scenario', 'normal')
    rate     = float(data.get('rate', 2.0))
    if generator.is_running():
        generator.update(scenario=scenario, rate=rate)
    else:
        engine.reset_state()
        generator.start(scenario=scenario, rate=rate)
    return jsonify({'ok': True, 'scenario': scenario, 'rate': rate})

@app.route('/api/simulate/stop', methods=['POST'])
def api_sim_stop():
    generator.stop()
    return jsonify({'ok': True})

@app.route('/api/simulate/update', methods=['POST'])
def api_sim_update():
    data = request.get_json(silent=True) or {}
    generator.update(
        scenario=data.get('scenario'),
        rate=float(data['rate']) if 'rate' in data else None
    )
    return jsonify({'ok': True})

@app.route('/api/simulate/status')
def api_sim_status():
    return jsonify({
        'running':  generator.is_running(),
        'scenario': generator.scenario,
        'rate':     generator.rate,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# LEARNING MODE API
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/learning/start', methods=['POST'])
def api_learning_start():
    engine.learning_mode = True
    if not generator.is_running():
        generator.start(scenario='normal', rate=5.0)
    return jsonify({'ok': True})

@app.route('/api/learning/stop', methods=['POST'])
def api_learning_stop():
    engine.learning_mode = False
    stats = engine.get_baseline_stats()
    # Persist baselines
    for proto, s in stats.items():
        db.upsert_baseline(proto, s['avg_size'], 0.0, s['sample_count'])
    return jsonify({'ok': True, 'baselines': stats})

@app.route('/api/learning/baseline')
def api_learning_baseline():
    return jsonify(db.get_baselines())


# ═══════════════════════════════════════════════════════════════════════════════
# DB INSPECTOR API
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/db/schema')
def api_db_schema():
    return jsonify(inspector.get_schema())

@app.route('/api/db/tables/<table>')
def api_db_table(table):
    page      = int(request.args.get('page', 1))
    per_page  = int(request.args.get('per_page', 25))
    filter_col = request.args.get('filter_col')
    filter_val = request.args.get('filter_val')
    sort_col  = request.args.get('sort_col', 'id')
    sort_dir  = request.args.get('sort_dir', 'DESC')
    return jsonify(inspector.get_table_rows(
        table, page, per_page, filter_col, filter_val, sort_col, sort_dir
    ))

@app.route('/api/db/query', methods=['POST'])
def api_db_query():
    data = request.get_json(silent=True) or {}
    sql  = data.get('sql', '').strip()
    return jsonify(inspector.run_query(sql))

@app.route('/api/db/counts')
def api_db_counts():
    return jsonify(inspector.get_table_counts())

@app.route('/api/db/vacuum', methods=['POST'])
def api_db_vacuum():
    db.vacuum_db()
    return jsonify({'ok': True})

@app.route('/api/db/purge', methods=['POST'])
def api_db_purge():
    data = request.get_json(silent=True) or {}
    days = int(data.get('days', 7))
    deleted = db.purge_old_traffic(days)
    return jsonify({'ok': True, 'deleted': deleted})


# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT API
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/export/json')
def api_export_json():
    payload = {
        'traffic': db.export_traffic_records(1000),
        'alerts':  db.export_alert_records(500),
    }
    return Response(
        json.dumps(payload, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=nmids_export.json'}
    )

@app.route('/api/export/csv')
def api_export_csv():
    rows    = db.export_traffic_records(1000)
    output  = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=nmids_traffic.csv'}
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
