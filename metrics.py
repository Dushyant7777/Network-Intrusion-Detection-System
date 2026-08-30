"""
metrics.py
----------
Fast, in-memory rolling statistics for the live dashboard. Deliberately
separate from the SQLite layer: the dashboard polls every couple of
seconds, and recomputing aggregates from disk on every poll would be
wasteful. Alerts are still persisted to the database (see database.py) --
this module just tracks the numbers that back the stat cards and charts
for the *current* capture session.
"""

import threading
import time
from collections import defaultdict, deque

TIMELINE_SECONDS = 90


class MetricsTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._reset_locked()

    def reset_session(self):
        with self._lock:
            self._reset_locked()

    def _reset_locked(self):
        self.total_packets = 0
        self.protocol_counts = defaultdict(int)
        self.severity_counts = defaultdict(int)
        self.top_talkers = defaultdict(int)
        self.timeline = deque(maxlen=TIMELINE_SECONDS)
        self._current_bucket = None
        self._current_count = 0
        self.session_start = time.time()
        self.last_packet_at = None

    def record_packet(self, pkt):
        with self._lock:
            self.total_packets += 1
            self.protocol_counts[pkt["protocol"]] += 1
            if pkt.get("src_ip"):
                self.top_talkers[pkt["src_ip"]] += 1
            self.last_packet_at = pkt["timestamp"]

            bucket = int(pkt["timestamp"])
            if self._current_bucket is None:
                self._current_bucket = bucket
            if bucket != self._current_bucket:
                self.timeline.append({"t": self._current_bucket, "count": self._current_count})
                self._current_bucket = bucket
                self._current_count = 0
            self._current_count += 1

    def record_alert(self, alert):
        with self._lock:
            self.severity_counts[alert["severity"]] += 1

    def get_stats(self):
        with self._lock:
            timeline = list(self.timeline)
            if self._current_bucket is not None:
                timeline = timeline + [{"t": self._current_bucket, "count": self._current_count}]
            top = sorted(self.top_talkers.items(), key=lambda kv: -kv[1])[:6]
            return {
                "total_packets": self.total_packets,
                "protocol_counts": dict(self.protocol_counts),
                "severity_counts": dict(self.severity_counts),
                "timeline": timeline[-60:],
                "top_talkers": [{"ip": ip, "count": c} for ip, c in top],
                "session_start": self.session_start,
                "last_packet_at": self.last_packet_at,
            }
