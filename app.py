import sys
import os
from pathlib import Path
from flask import Flask, render_template, request, jsonify, redirect, url_for

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.storage import (
    init_db, get_alerts, get_events, get_summary,
    update_alert_status, get_alerts_by_severity, get_alerts_by_type,
)

try:
    from correlator.engine import get_incidents, init_incidents_table
except ImportError:
    def get_incidents(): return []
    def init_incidents_table(): pass

try:
    from enrichment.attack_mapper import summarize_attack_coverage, ATTACK_TECHNIQUES
except ImportError:
    def summarize_attack_coverage(alerts): return {"tactics": {}, "techniques": [], "total_techniques": 0, "total_tactics": 0}
    ATTACK_TECHNIQUES = {}

app = Flask(__name__, template_folder="dashboard", static_folder="dashboard")


# ─────────────────────────────────────────────
#  SEVERITY ORDERING — used for sort across views
# ─────────────────────────────────────────────

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def sort_by_severity(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda x: SEVERITY_RANK.get(x.get("severity", "LOW"), 9))


# ─────────────────────────────────────────────
#  ROUTES — PAGES
# ─────────────────────────────────────────────

@app.route("/")
def dashboard():
    """Main dashboard — overview cards + recent alerts."""
    summary  = get_summary()
    alerts   = sort_by_severity(get_alerts())[:10]   # most critical first, top 10
    incidents = get_incidents()[:5]

    coverage = summarize_attack_coverage(get_alerts())

    return render_template(
        "dashboard.html",
        summary=summary,
        alerts=alerts,
        incidents=incidents,
        coverage=coverage,
        active_page="dashboard",
    )


@app.route("/alerts")
def alerts_view():
    """Full alert list with filtering."""
    severity_filter = request.args.get("severity", "ALL")
    type_filter     = request.args.get("type", "ALL")

    if severity_filter != "ALL":
        alerts = get_alerts_by_severity(severity_filter)
    elif type_filter != "ALL":
        alerts = get_alerts_by_type(type_filter)
    else:
        alerts = get_alerts()

    alerts = sort_by_severity(alerts)

    all_alerts   = get_alerts()
    alert_types  = sorted(set(a["alert_type"] for a in all_alerts))

    return render_template(
        "alerts.html",
        alerts=alerts,
        alert_types=alert_types,
        current_severity=severity_filter,
        current_type=type_filter,
        active_page="alerts",
    )


@app.route("/alert/<int:alert_id>")
def alert_detail(alert_id):
    """Single alert detail view with raw evidence."""
    all_alerts = get_alerts()
    alert = next((a for a in all_alerts if a["id"] == alert_id), None)

    if not alert:
        return render_template("404.html"), 404

    import json
    raw_events = []
    try:
        raw_events = json.loads(alert.get("raw_events", "[]"))
    except (json.JSONDecodeError, TypeError):
        pass

    technique = ATTACK_TECHNIQUES.get(alert.get("attack_id", ""), {})

    return render_template(
        "alert_detail.html",
        alert=alert,
        raw_events=raw_events,
        technique=technique,
        active_page="alerts",
    )


@app.route("/incidents")
def incidents_view():
    """Correlated incidents — the kill-chain view."""
    incidents = sort_by_severity(get_incidents())
    return render_template(
        "incidents.html",
        incidents=incidents,
        active_page="incidents",
    )


@app.route("/incident/<int:incident_id>")
def incident_detail(incident_id):
    """Single incident with full timeline."""
    incidents = get_incidents()
    incident = next((i for i in incidents if i["id"] == incident_id), None)

    if not incident:
        return render_template("404.html"), 404

    return render_template(
        "incident_detail.html",
        incident=incident,
        active_page="incidents",
    )


@app.route("/attack-matrix")
def attack_matrix():
    """ATT&CK technique coverage view."""
    alerts   = get_alerts()
    coverage = summarize_attack_coverage(alerts)

    return render_template(
        "attack_matrix.html",
        coverage=coverage,
        techniques=ATTACK_TECHNIQUES,
        active_page="attack-matrix",
    )


@app.route("/events")
def events_view():
    """Raw parsed event log browser."""
    log_type_filter = request.args.get("log_type", "ALL")
    events = get_events(limit=200)

    if log_type_filter != "ALL":
        events = [e for e in events if e.get("log_type") == log_type_filter]

    log_types = sorted(set(e["log_type"] for e in get_events(limit=1000) if e.get("log_type")))

    return render_template(
        "events.html",
        events=events,
        log_types=log_types,
        current_log_type=log_type_filter,
        active_page="events",
    )


# ─────────────────────────────────────────────
#  ROUTES — ACTIONS
# ─────────────────────────────────────────────

@app.route("/alert/<int:alert_id>/status", methods=["POST"])
def update_status(alert_id):
    """Update an alert's investigation status."""
    new_status = request.form.get("status", "open")
    update_alert_status(alert_id, new_status)
    return redirect(url_for("alert_detail", alert_id=alert_id))


# ─────────────────────────────────────────────
#  ROUTES — JSON API (for future automation / export)
# ─────────────────────────────────────────────

@app.route("/api/summary")
def api_summary():
    return jsonify(get_summary())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(sort_by_severity(get_alerts()))


@app.route("/api/incidents")
def api_incidents():
    return jsonify(get_incidents())


# ─────────────────────────────────────────────
#  TEMPLATE FILTERS
# ─────────────────────────────────────────────

@app.template_filter("severity_class")
def severity_class(severity):
    """Map severity string to CSS class suffix."""
    return {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
    }.get(severity, "low")


@app.template_filter("short_time")
def short_time(iso_timestamp):
    """Format an ISO timestamp into something compact for tables."""
    if not iso_timestamp:
        return "—"
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(iso_timestamp)
        return dt.strftime("%b %d, %H:%M:%S")
    except (ValueError, TypeError):
        return iso_timestamp[:19] if len(iso_timestamp) >= 19 else iso_timestamp


@app.template_filter("truncate_text")
def truncate_text(text, length=80):
    if not text:
        return ""
    return text if len(text) <= length else text[:length] + "…"


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    init_incidents_table()
    app.run(debug=True, host="0.0.0.0", port=5000)