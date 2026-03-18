"""
HIDS Web Dashboard — Flask app
All API endpoints for the rich analytics dashboard.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json, time
from flask import Flask, render_template, jsonify, Response, stream_with_context
from core.db import (get_recent_alerts, get_threat_breakdown, get_severity_counts,
                     get_hourly_stats, get_daily_heatmap, get_sessions, get_summary)

STATE_FILE = os.environ.get("HIDS_STATE", "/var/lib/hids/state.json")
DB_PATH    = os.environ.get("HIDS_DB",    "/var/lib/hids/hids.db")

app = Flask(__name__)

def read_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"status":"starting","stats":{"alerts":0,"suppressed":0,"scans":0,"syscalls":0}}

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

# ── Live state ────────────────────────────────────────────────────────────────
@app.route("/api/state")
def api_state():
    return jsonify(read_state())

# ── Analytics ─────────────────────────────────────────────────────────────────
@app.route("/api/summary")
def api_summary():
    return jsonify(get_summary())

@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_recent_alerts(200))

@app.route("/api/alerts/live")
def api_alerts_live():
    return jsonify(get_recent_alerts(20))

@app.route("/api/threat-breakdown")
def api_threat_breakdown():
    return jsonify(get_threat_breakdown())

@app.route("/api/severity-counts")
def api_severity_counts():
    return jsonify(get_severity_counts())

@app.route("/api/hourly")
def api_hourly():
    return jsonify(get_hourly_stats(48))

@app.route("/api/heatmap")
def api_heatmap():
    return jsonify(get_daily_heatmap(60))

@app.route("/api/sessions")
def api_sessions():
    return jsonify(get_sessions(20))

# ── SSE live feed ─────────────────────────────────────────────────────────────
@app.route("/stream")
def stream():
    """Server-Sent Events — polls state every 2s and pushes changes."""
    def gen():
        last_scan = -1
        while True:
            state = read_state()
            sc = state.get("scan_count", 0)
            if sc != last_scan:
                last_scan = sc
                yield f"data: {json.dumps(state)}\n\n"
            time.sleep(1.5)
    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"}
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
