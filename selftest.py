"""Quick, deterministic sanity tests for the core logic modules.
Run directly: python3 selftest.py
"""
import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database as db
import auth
from detection import DetectionEngine

PASS, FAIL = [], []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("  OK  " if cond else " FAIL "), name)


# ---------------------------------------------------------------- database
print("== database.py ==")
tmp_db = tempfile.mktemp(suffix=".db")
db.init_db(tmp_db)
conn = db.get_connection(tmp_db)

db.insert_packets_batch(conn, [
    {"timestamp": time.time(), "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "protocol": "TCP",
     "src_port": 5555, "dst_port": 80, "size": 512, "flags": "PA"}
    for _ in range(10)
])
check("insert_packets_batch + count", db.get_total_packet_count(conn) == 10)

alert_id = db.insert_alert(conn, {
    "timestamp": time.time(), "alert_type": "Port Scan", "severity": "High",
    "src_ip": "203.0.113.9", "dst_ip": "10.0.0.1", "description": "test alert",
    "details": {"port_count": 40},
})
check("insert_alert returns id", isinstance(alert_id, int))
alerts = db.get_recent_alerts(conn, limit=10)
check("get_recent_alerts returns it, details round-trips via JSON", len(alerts) == 1 and alerts[0]["details"]["port_count"] == 40)
check("get_alert_counts_by_severity", db.get_alert_counts_by_severity(conn) == {"High": 1})
check("get_alerts_by_type", db.get_alerts_by_type(conn)[0]["alert_type"] == "Port Scan")
check("get_top_alert_sources", db.get_top_alert_sources(conn)[0]["src_ip"] == "203.0.113.9")

db.prune_old_packets(conn, keep_last=3)
check("prune_old_packets caps table", db.get_total_packet_count(conn) == 3)

# ---------------------------------------------------------------- auth
print("\n== auth.py ==")
seeded = auth.seed_default_admin(conn)
check("seed_default_admin creates one on empty table", seeded is True)
seeded_again = auth.seed_default_admin(conn)
check("seed_default_admin is a no-op the 2nd time", seeded_again is False)

ok, msg, is_default, is_admin = auth.verify_login(conn, "admin", "admin123")
check("verify_login accepts correct default creds", ok and is_default)
check("seeded admin account is flagged is_admin", is_admin is True)
ok, msg, is_default, is_admin = auth.verify_login(conn, "admin", "wrong-password")
check("verify_login rejects wrong password", not ok)

for _ in range(auth.MAX_FAILED_ATTEMPTS):
    auth.verify_login(conn, "bruteforce_test_user", "nope")
ok, msg, _, _ = auth.verify_login(conn, "bruteforce_test_user", "nope")
check("brute-force lockout kicks in after N failures", not ok and "Too many" in msg)

ok, msg = auth.change_password(conn, "admin", "admin123", "newpassword456")
check("change_password with correct current password", ok)
ok, _, _, _ = auth.verify_login(conn, "admin", "newpassword456")
check("login works with new password", ok)
ok, _, _, _ = auth.verify_login(conn, "admin", "admin123")
check("old password no longer works", not ok)

# -- migration safety net: a pre-roles 'admin' row should get flagged --
conn.execute("UPDATE users SET is_admin = 0 WHERE username = 'admin'")
conn.commit()
auth.ensure_admin_flag(conn)
_, _, _, is_admin = auth.verify_login(conn, "admin", "newpassword456")
check("ensure_admin_flag restores admin status on an old/downgraded row", is_admin is True)

# -- self-service signup (register_user) --
ok, msg = auth.register_user(conn, "new_analyst", "hunter2pass", "hunter2pass", ip="10.1.1.1")
check("register_user creates a valid new account", ok)
ok, _, _, is_admin = auth.verify_login(conn, "new_analyst", "hunter2pass")
check("newly registered user can log in", ok)
check("self-registered account is NOT admin", is_admin is False)
ok, msg = auth.register_user(conn, "new_analyst", "differentpass1", "differentpass1", ip="10.1.1.1")
check("register_user rejects a duplicate username", not ok and "already taken" in msg)
ok, msg = auth.register_user(conn, "someone_new", "abc123", "xyz789", ip="10.1.1.1")
check("register_user rejects mismatched passwords", not ok and "match" in msg)
ok, msg = auth.register_user(conn, "ab", "goodpassword1", "goodpassword1", ip="10.1.1.1")
check("register_user rejects too-short username", not ok)
ok, msg = auth.register_user(conn, "valid_user2", "short", "short", ip="10.1.1.1")
check("register_user rejects too-short password", not ok)
ok, msg = auth.register_user(conn, "bad name!", "goodpassword1", "goodpassword1", ip="10.1.1.1")
check("register_user rejects invalid characters in username", not ok)
ok, _, _, _ = auth.verify_login(conn, "admin", "newpassword456")
check("original admin account still logs in fine after signup activity", ok)

# -- per-IP signup rate limiting --
limited_hit = False
for i in range(auth.MAX_SIGNUPS_PER_IP + 2):
    ok, msg = auth.register_user(conn, f"ratelimit_user_{i}", "goodpassword1", "goodpassword1", ip="10.2.2.2")
    if not ok and "Too many accounts" in msg:
        limited_hit = True
        break
check("signup is rate-limited per IP after MAX_SIGNUPS_PER_IP", limited_hit)
ok, msg = auth.register_user(conn, "different_ip_user", "goodpassword1", "goodpassword1", ip="10.3.3.3")
check("a different IP is unaffected by another IP's signup rate limit", ok)

conn.close()
os.remove(tmp_db)

# ------------------------------------------------------------- detection
print("\n== detection.py ==")
engine = DetectionEngine()
now = time.time()

# 1) baseline "normal" traffic -- should NOT alert
alerts = []
for i in range(5):
    alerts += engine.process_packet({
        "timestamp": now + i * 0.1, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.1",
        "protocol": "TCP", "src_port": 40000 + i, "dst_port": 443, "size": 300, "flags": "PA",
    })
check("normal light traffic produces no alerts", len(alerts) == 0)

# 2) port scan: one source hitting many distinct ports fast
alerts = []
t0 = time.time()
for i, port in enumerate(range(1, 30)):
    alerts += engine.process_packet({
        "timestamp": t0 + i * 0.05, "src_ip": "203.0.113.50", "dst_ip": "192.168.1.20",
        "protocol": "TCP", "src_port": 51000, "dst_port": port, "size": 60, "flags": "S",
    })
port_scan_alerts = [a for a in alerts if a["alert_type"] == "Port Scan"]
check("port scan burst triggers a Port Scan alert", len(port_scan_alerts) >= 1)
check("port scan alert has a valid severity", port_scan_alerts and port_scan_alerts[0]["severity"] in ("Medium", "High", "Critical"))

# 3) SYN flood: many SYN-only packets to one destination
engine2 = DetectionEngine()
alerts = []
t0 = time.time()
for i in range(80):
    alerts += engine2.process_packet({
        "timestamp": t0 + i * 0.01, "src_ip": "198.51.100.7", "dst_ip": "192.168.1.5",
        "protocol": "TCP", "src_port": 52000 + i, "dst_port": 80, "size": 60, "flags": "S",
    })
syn_alerts = [a for a in alerts if a["alert_type"] == "SYN Flood"]
check("SYN flood burst triggers a SYN Flood alert", len(syn_alerts) >= 1)

# 4) legit handshake traffic (SYN+ACK / ACK) should NOT trigger SYN flood
engine3 = DetectionEngine()
alerts = []
t0 = time.time()
for i in range(80):
    alerts += engine3.process_packet({
        "timestamp": t0 + i * 0.01, "src_ip": "198.51.100.7", "dst_ip": "192.168.1.5",
        "protocol": "TCP", "src_port": 52000 + i, "dst_port": 80, "size": 60, "flags": "SA",
    })
check("SYN+ACK packets (real handshakes) do not trigger SYN flood", len([a for a in alerts if a['alert_type']=='SYN Flood']) == 0)

# 5) ICMP flood
engine4 = DetectionEngine()
alerts = []
t0 = time.time()
for i in range(80):
    alerts += engine4.process_packet({
        "timestamp": t0 + i * 0.01, "src_ip": "203.0.113.99", "dst_ip": "192.168.1.5",
        "protocol": "ICMP", "src_port": None, "dst_port": None, "size": 64, "flags": "type=8",
    })
icmp_alerts = [a for a in alerts if a["alert_type"] == "ICMP Flood"]
check("ICMP flood burst triggers an ICMP Flood alert", len(icmp_alerts) >= 1)

# 6) cooldown: sustained attack doesn't spam one alert per packet
check("cooldown suppresses duplicate alerts (fewer alerts than packets)", len(icmp_alerts) < 80)

# 7) statistical anomaly: quiet baseline then a sharp spike
engine5 = DetectionEngine()
t0 = time.time()
alerts = []
for sec in range(30):  # establish a quiet ~2 pkt/s baseline
    for _ in range(2):
        alerts += engine5.process_packet({
            "timestamp": t0 + sec + 0.01, "src_ip": "192.168.1.30", "dst_ip": "192.168.1.1",
            "protocol": "UDP", "src_port": 5000, "dst_port": 53, "size": 80, "flags": None,
        })
spike_t = t0 + 31
for _ in range(60):  # sudden spike within the same second
    alerts += engine5.process_packet({
        "timestamp": spike_t, "src_ip": "192.168.1.31", "dst_ip": "192.168.1.1",
        "protocol": "UDP", "src_port": 5001, "dst_port": 53, "size": 80, "flags": None,
    })
anomaly_alerts = [a for a in alerts if a["alert_type"] == "Traffic Anomaly"]
check("sharp rate spike after a quiet baseline triggers a Traffic Anomaly alert", len(anomaly_alerts) >= 1)

# ------------------------------------------------------------------ summary
print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
sys.exit(0)
