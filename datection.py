"""
detection.py
------------
In-memory detection engine. Runs entirely against a stream of packet-
metadata dicts (timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
size, flags) -- it does not care whether that stream came from real
Scapy capture or the built-in simulator; both call the same
process_packet() method.

Implements four detection rules from the project brief:
  1. Port scan       - one source IP touching many distinct destination
                        ports in a short window
  2. SYN flood       - a burst of TCP SYN (no-ACK) packets from one source
  3. ICMP flood      - a burst of ICMP echo requests from one source
  4. Traffic anomaly - overall packet rate deviates sharply (z-score) from
                        its own recent rolling baseline: a simple
                        statistical stand-in for the "optional ML-based
                        anomaly detection" called out in the brief

Each rule has a short per-(type, source) cooldown so one sustained
condition produces periodic alerts instead of one alert per packet.
"""

import statistics
import threading
from collections import defaultdict, deque

# ---- Tunable thresholds ------------------------------------------------
PORT_SCAN_PORT_THRESHOLD = 15
PORT_SCAN_WINDOW_SECONDS = 10

SYN_FLOOD_PACKET_THRESHOLD = 50
SYN_FLOOD_WINDOW_SECONDS = 5

ICMP_FLOOD_PACKET_THRESHOLD = 50
ICMP_FLOOD_WINDOW_SECONDS = 5

ANOMALY_MIN_BASELINE_SAMPLES = 20
ANOMALY_ZSCORE_THRESHOLD = 3.0
ANOMALY_MIN_RATE = 10  # ignore spikes below this pkts/sec -- too small to matter

ALERT_COOLDOWN_SECONDS = 20


def _severity_from_scale(value, bands):
    """bands: [(upper_bound_exclusive, severity), ...] checked in order."""
    for bound, severity in bands:
        if value < bound:
            return severity
    return bands[-1][1]


class DetectionEngine:
    def __init__(self):
        self._lock = threading.Lock()

        self._port_scan = defaultdict(dict)                      # src_ip -> {port: last_seen_ts}
        self._syn = defaultdict(lambda: deque(maxlen=2000))       # src_ip -> deque[ts]
        self._icmp = defaultdict(lambda: deque(maxlen=2000))      # src_ip -> deque[ts]

        self._rate_window = deque(maxlen=60)   # completed-second packet counts
        self._current_bucket = None
        self._current_bucket_count = 0

        self._cooldowns = {}  # (alert_type, src_ip) -> last_fired_ts

    # -- public API --------------------------------------------------

    def process_packet(self, pkt):
        """Feed one packet dict in; get back a list of 0+ new alert dicts."""
        alerts = []
        ts = pkt["timestamp"]
        with self._lock:
            self._tick_rate(ts)

            if pkt["protocol"] == "TCP":
                a = self._check_port_scan(pkt, ts)
                if a:
                    alerts.append(a)
                a = self._check_syn_flood(pkt, ts)
                if a:
                    alerts.append(a)
            elif pkt["protocol"] == "ICMP":
                a = self._check_icmp_flood(pkt, ts)
                if a:
                    alerts.append(a)

            a = self._check_anomaly(ts)
            if a:
                alerts.append(a)
        return alerts

    def reset(self):
        with self._lock:
            self._port_scan.clear()
            self._syn.clear()
            self._icmp.clear()
            self._rate_window.clear()
            self._current_bucket = None
            self._current_bucket_count = 0
            self._cooldowns.clear()

    # -- rate tracking (feeds the anomaly rule) -----------------------

    def _tick_rate(self, ts):
        bucket = int(ts)
        if self._current_bucket is None:
            self._current_bucket = bucket
        if bucket != self._current_bucket:
            self._rate_window.append(self._current_bucket_count)
            self._current_bucket = bucket
            self._current_bucket_count = 0
        self._current_bucket_count += 1

    # -- rule 1: port scan ---------------------------------------------

    def _check_port_scan(self, pkt, ts):
        src, port = pkt["src_ip"], pkt["dst_port"]
        if src is None or port is None:
            return None
        ports = self._port_scan[src]
        ports[port] = ts
        cutoff = ts - PORT_SCAN_WINDOW_SECONDS
        for p in [p for p, seen in ports.items() if seen < cutoff]:
            del ports[p]

        if len(ports) >= PORT_SCAN_PORT_THRESHOLD and self._ready(("Port Scan", src), ts):
            severity = _severity_from_scale(len(ports), [(25, "Medium"), (45, "High"), (float("inf"), "Critical")])
            return self._make_alert(
                ts, "Port Scan", severity, src, pkt["dst_ip"],
                f"{src} probed {len(ports)} distinct ports on {pkt['dst_ip']} within {PORT_SCAN_WINDOW_SECONDS}s.",
                {"port_count": len(ports), "ports_sample": sorted(ports.keys())[:20]},
            )
        return None

    # -- rule 2: SYN flood -----------------------------------------------

    def _check_syn_flood(self, pkt, ts):
        flags = pkt.get("flags") or ""
        if "S" not in flags or "A" in flags:  # want SYN set, ACK not set
            return None
        src = pkt["src_ip"]
        dq = self._syn[src]
        dq.append(ts)
        cutoff = ts - SYN_FLOOD_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= SYN_FLOOD_PACKET_THRESHOLD and self._ready(("SYN Flood", src), ts):
            severity = _severity_from_scale(len(dq), [(100, "Medium"), (200, "High"), (float("inf"), "Critical")])
            return self._make_alert(
                ts, "SYN Flood", severity, src, pkt["dst_ip"],
                f"{src} sent {len(dq)} SYN packets to {pkt['dst_ip']} in {SYN_FLOOD_WINDOW_SECONDS}s without completing the handshake.",
                {"syn_count": len(dq), "window_seconds": SYN_FLOOD_WINDOW_SECONDS},
            )
        return None

    # -- rule 3: ICMP flood ----------------------------------------------

    def _check_icmp_flood(self, pkt, ts):
        src = pkt["src_ip"]
        dq = self._icmp[src]
        dq.append(ts)
        cutoff = ts - ICMP_FLOOD_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= ICMP_FLOOD_PACKET_THRESHOLD and self._ready(("ICMP Flood", src), ts):
            severity = _severity_from_scale(len(dq), [(100, "Medium"), (200, "High"), (float("inf"), "Critical")])
            return self._make_alert(
                ts, "ICMP Flood", severity, src, pkt["dst_ip"],
                f"{src} sent {len(dq)} ICMP echo requests to {pkt['dst_ip']} in {ICMP_FLOOD_WINDOW_SECONDS}s.",
                {"icmp_count": len(dq), "window_seconds": ICMP_FLOOD_WINDOW_SECONDS},
            )
        return None

    # -- rule 4: statistical traffic anomaly ------------------------------

    def _check_anomaly(self, ts):
        if len(self._rate_window) < ANOMALY_MIN_BASELINE_SAMPLES:
            return None
        history = list(self._rate_window)
        mean = statistics.mean(history)
        stdev = statistics.pstdev(history) or 1.0
        current = self._current_bucket_count
        z = (current - mean) / stdev

        if current >= ANOMALY_MIN_RATE and z >= ANOMALY_ZSCORE_THRESHOLD and self._ready(("Traffic Anomaly", "network"), ts):
            severity = _severity_from_scale(z, [(4, "Medium"), (6, "High"), (float("inf"), "Critical")])
            return self._make_alert(
                ts, "Traffic Anomaly", severity, None, None,
                f"Packet rate spiked to {current}/s, {z:.1f} standard deviations above the recent baseline of {mean:.1f}/s.",
                {"current_rate": current, "baseline_mean": round(mean, 2), "z_score": round(z, 2)},
            )
        return None

    # -- shared helpers ------------------------------------------------

    def _ready(self, key, ts):
        last = self._cooldowns.get(key)
        if last is not None and ts - last < ALERT_COOLDOWN_SECONDS:
            return False
        self._cooldowns[key] = ts
        return True

    @staticmethod
    def _make_alert(ts, alert_type, severity, src_ip, dst_ip, description, details):
        return {
            "timestamp": ts,
            "alert_type": alert_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "description": description,
            "details": details,
        }
