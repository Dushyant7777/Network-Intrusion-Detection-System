"""
app.py
------
Flask application tying together the database, detection engine, metrics
tracker, live Scapy capture, and traffic simulator behind a REST API, and
serving the login + dashboard pages.

"""

import os
import csv
import io
import time
import threading

from flask import Flask, render_template, jsonify, request, redirect, url_for, session, Response

import database as db
import auth
from detection import DetectionEngine
from metrics import MetricsTracker
import capture as capture_module
from simulator import TrafficSimulator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "nids.db")
SECRET_KEY_PATH = os.path.join(BASE_DIR, ".secret_key")


def _load_or_create_secret_key():
    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "rb") as f:
            key = f.read()
            if key:
                return key
    key = os.urandom(32)
    with open(SECRET_KEY_PATH, "wb") as f:
        f.write(key)
    return key


def _safe_next(url):
    """Only allow same-site relative redirects after login (blocks open-redirect)."""
    if url and url.startswith("/") and not url.startswith("//"):
        return url
    return url_for("index")


app = Flask(__name__)
env_key = os.environ.get("NIDS_SECRET_KEY", "")
app.secret_key = env_key.encode() if env_key else _load_or_create_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Self-service signup is on by default (handy for local/portfolio use).
# Set NIDS_ALLOW_SIGNUP=false before deploying somewhere more public if you
# want the seeded admin to be the only account, or to hand out accounts
# yourself instead. See README > Security Notes.
ALLOW_SIGNUP = os.environ.get("NIDS_ALLOW_SIGNUP", "true").strip().lower() not in ("false", "0", "no")

# ------------------------------------------------------------------ setup --

db.init_db(DB_PATH)

_setup_conn = db.get_connection(DB_PATH)
_seeded = auth.seed_default_admin(_setup_conn)
auth.ensure_admin_flag(_setup_conn)  # no-op except when upgrading a pre-roles database
_setup_conn.close()
if _seeded:
    print("=" * 72)
    print(f"  First run: created default login  {auth.DEFAULT_ADMIN_USERNAME} / {auth.DEFAULT_ADMIN_PASSWORD}")
    print("  Log in and change this password right away (Account > Change Password).")
    print("=" * 72)
if not ALLOW_SIGNUP:
    print("  NIDS_ALLOW_SIGNUP=false -- self-service signup is disabled.")

detection_engine = DetectionEngine()
metrics = MetricsTracker()

_packet_buffer = []
_buffer_lock = threading.Lock()

state = {"mode": None, "interface": None, "start_time": None}
_state_lock = threading.Lock()


def handle_packet(pkt):
    """Called from the capture/simulator background thread for every packet."""
    metrics.record_packet(pkt)
    with _buffer_lock:
        _packet_buffer.append(pkt)

    for alert in detection_engine.process_packet(pkt):
        metrics.record_alert(alert)
        conn = db.get_connection(DB_PATH)
        try:
            db.insert_alert(conn, alert)
        finally:
            conn.close()


live_capture = capture_module.LiveCapture(on_packet=handle_packet)
simulator = TrafficSimulator(on_packet=handle_packet)


def _flush_loop():
    while True:
        time.sleep(1)
        with _buffer_lock:
            batch, _packet_buffer[:] = _packet_buffer[:], []
        if batch:
            conn = db.get_connection(DB_PATH)
            try:
                db.insert_packets_batch(conn, batch)
                db.prune_old_packets(conn, keep_last=5000)
            finally:
                conn.close()


threading.Thread(target=_flush_loop, daemon=True).start()


def _current_mode_running():
    if state["mode"] == "live":
        return live_capture.running
    if state["mode"] == "simulation":
        return simulator.running
    return False


# -------------------------------------------------------------- page routes --

@app.route("/login", methods=["GET"])
def login_page():
    if session.get("username"):
        return redirect(url_for("index"))
    return render_template("login.html", error=None, next_url=request.args.get("next", ""), allow_signup=ALLOW_SIGNUP)


@app.route("/login", methods=["POST"])
def login_submit():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    conn = db.get_connection(DB_PATH)
    try:
        ok, message, is_default, is_admin = auth.verify_login(conn, username, password)
    finally:
        conn.close()

    if not ok:
        return render_template("login.html", error=message, next_url=request.form.get("next", ""), allow_signup=ALLOW_SIGNUP), 401

    session.clear()
    session["username"] = username
    session["using_default_password"] = is_default
    session["is_admin"] = is_admin
    return redirect(_safe_next(request.form.get("next", "")))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/signup", methods=["GET"])
def signup_page():
    if session.get("username"):
        return redirect(url_for("index"))
    if not ALLOW_SIGNUP:
        return redirect(url_for("login_page"))
    return render_template("signup.html", error=None, prefill_username="")


@app.route("/signup", methods=["POST"])
def signup_submit():
    if not ALLOW_SIGNUP:
        return redirect(url_for("login_page"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    conn = db.get_connection(DB_PATH)
    try:
        ok, message = auth.register_user(conn, username, password, confirm_password, ip=request.remote_addr)
    finally:
        conn.close()

    if not ok:
        return render_template("signup.html", error=message, prefill_username=username), 400

    session.clear()
    session["username"] = username
    session["using_default_password"] = False
    session["is_admin"] = False
    return redirect(url_for("index"))


@app.route("/")
@auth.login_required
def index():
    return render_template(
        "index.html",
        username=session.get("username"),
        using_default_password=bool(session.get("using_default_password")),
        is_admin=bool(session.get("is_admin")),
        scapy_available=capture_module.SCAPY_AVAILABLE,
    )


# --------------------------------------------------------------- api routes --

@app.route("/api/account/change-password", methods=["POST"])
@auth.api_login_required
def api_change_password():
    data = request.get_json(force=True, silent=True) or {}
    conn = db.get_connection(DB_PATH)
    try:
        ok, message = auth.change_password(
            conn, session["username"], data.get("current_password", ""), data.get("new_password", "")
        )
    finally:
        conn.close()
    if ok:
        session["using_default_password"] = False
    return jsonify({"success": ok, "message": message})


@app.route("/api/interfaces")
@auth.api_login_required
def api_interfaces():
    return jsonify({
        "interfaces": live_capture.list_interfaces(),
        "scapy_available": capture_module.SCAPY_AVAILABLE,
        "scapy_import_error": capture_module.SCAPY_IMPORT_ERROR,
    })


@app.route("/api/capture/start", methods=["POST"])
@auth.api_login_required
def api_capture_start():
    data = request.get_json(force=True, silent=True) or {}
    mode = data.get("mode", "simulation")
    interface = data.get("interface") or None

    with _state_lock:
        if _current_mode_running():
            return jsonify({"success": False, "message": "Capture is already running. Stop it first."}), 400

        if mode == "live":
            if not live_capture.start(interface=interface):
                return jsonify({"success": False, "message": live_capture.error}), 400
        elif mode == "simulation":
            simulator.start()
        else:
            return jsonify({"success": False, "message": "mode must be 'live' or 'simulation'"}), 400

        detection_engine.reset()
        metrics.reset_session()
        state.update({"mode": mode, "interface": interface, "start_time": time.time()})

    return jsonify({"success": True, "mode": mode, "interface": interface})


@app.route("/api/capture/stop", methods=["POST"])
@auth.api_login_required
def api_capture_stop():
    with _state_lock:
        if state["mode"] == "live":
            live_capture.stop()
        elif state["mode"] == "simulation":
            simulator.stop()
        state.update({"mode": None, "interface": None})
    return jsonify({"success": True})


@app.route("/api/capture/status")
@auth.api_login_required
def api_capture_status():
    return jsonify({
        "mode": state["mode"],
        "running": _current_mode_running(),
        "interface": state["interface"],
        "start_time": state["start_time"],
        "error": live_capture.error if state["mode"] == "live" else None,
        "scapy_available": capture_module.SCAPY_AVAILABLE,
    })


@app.route("/api/stats")
@auth.api_login_required
def api_stats():
    return jsonify(metrics.get_stats())


@app.route("/api/alerts")
@auth.api_login_required
def api_alerts():
    limit = request.args.get("limit", 50, type=int)
    severity = request.args.get("severity") or None
    alert_type = request.args.get("type") or None
    conn = db.get_connection(DB_PATH)
    try:
        alerts = db.get_recent_alerts(conn, limit=min(limit, 500), severity=severity, alert_type=alert_type)
    finally:
        conn.close()
    return jsonify({"alerts": alerts})


@app.route("/api/alerts/export")
@auth.api_login_required
def api_alerts_export():
    conn = db.get_connection(DB_PATH)
    try:
        alerts = db.get_recent_alerts(conn, limit=10000)
    finally:
        conn.close()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "datetime_utc", "alert_type", "severity", "src_ip", "dst_ip", "description"])
    for a in alerts:
        writer.writerow([
            a["timestamp"],
            time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(a["timestamp"])),
            a["alert_type"], a["severity"], a["src_ip"] or "", a["dst_ip"] or "", a["description"],
        ])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=nids_alerts_report.csv"},
    )


@app.route("/api/traffic")
@auth.api_login_required
def api_traffic():
    limit = request.args.get("limit", 50, type=int)
    conn = db.get_connection(DB_PATH)
    try:
        packets = db.get_recent_packets(conn, limit=min(limit, 500))
    finally:
        conn.close()
    return jsonify({"packets": packets})


@app.route("/api/reports")
@auth.api_login_required
def api_reports():
    days = request.args.get("days", 14, type=int)
    conn = db.get_connection(DB_PATH)
    try:
        result = {
            "alerts_by_day": db.get_alerts_by_day(conn, days=days),
            "alerts_by_type": db.get_alerts_by_type(conn),
            "top_sources": db.get_top_alert_sources(conn, limit=10),
            "alerts_by_severity": db.get_alert_counts_by_severity(conn),
            "total_packets_logged": db.get_total_packet_count(conn),
        }
    finally:
        conn.close()
    return jsonify(result)


@app.route("/api/admin/reset-data", methods=["POST"])
@auth.api_admin_required
def api_reset_data():
    conn = db.get_connection(DB_PATH)
    try:
        db.clear_all_data(conn)
    finally:
        conn.close()
    detection_engine.reset()
    metrics.reset_session()
    return jsonify({"success": True})


if __name__ == "__main__":
    host = os.environ.get("NIDS_HOST", "127.0.0.1")
    port = int(os.environ.get("NIDS_PORT", "5000"))
    print(f"\n  NIDS dashboard starting at http://{host}:{port}  (Ctrl+C to stop)\n")
    app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
