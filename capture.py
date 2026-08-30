"""
capture.py
----------
Real, live packet capture using Scapy. This is the module that actually
sniffs the wire.

Two hard requirements come with real sniffing, both outside this code's
control:
  1. Scapy must be installed (`pip install scapy`).
  2. The process needs raw-socket privileges: run as root/sudo on
     Linux/macOS, or as Administrator with Npcap installed on Windows.

Because of (1), the Scapy import is wrapped defensively -- if it's
missing, SCAPY_AVAILABLE is False and the rest of the app (Flask routes,
database, detection engine, Simulation Mode) still runs normally; the
dashboard just disables the "Live Capture" option and explains why.
Because of (2), start() catches permission errors and surfaces a plain-
English message instead of crashing the server.
"""

import threading
import time

try:
    from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = None
except Exception as e:  # ImportError normally, but be defensive
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(e)


class LiveCapture:
    def __init__(self, on_packet):
        self.on_packet = on_packet  # callback(packet_dict)
        self._thread = None
        self._stop_flag = threading.Event()
        self.running = False
        self.error = None
        self.interface = None

    def list_interfaces(self):
        if not SCAPY_AVAILABLE:
            return []
        try:
            return get_if_list()
        except Exception:
            return []

    def start(self, interface=None):
        if not SCAPY_AVAILABLE:
            self.error = (
                "Scapy is not installed in this Python environment. "
                "Run: pip install scapy"
            )
            return False
        if self.running:
            return True

        self._stop_flag.clear()
        self.error = None
        self.interface = interface or None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

        # give the sniffer a brief moment to fail fast on a permissions error
        time.sleep(0.4)
        if self.error:
            self.running = False
            return False
        self.running = True
        return True

    def stop(self):
        self._stop_flag.set()
        self.running = False

    # -- internals -----------------------------------------------------

    def _run(self):
        try:
            self.running = True
            # Loop sniff() with a short timeout so the stop flag is checked
            # regularly instead of blocking indefinitely on a quiet interface.
            while not self._stop_flag.is_set():
                sniff(
                    iface=self.interface,
                    prn=self._process,
                    store=False,
                    timeout=1,
                )
        except PermissionError:
            self.error = (
                "Permission denied opening a raw socket. Packet capture needs "
                "elevated privileges -- run with sudo (Linux/macOS) or as "
                "Administrator with Npcap installed (Windows)."
            )
        except OSError as e:
            self.error = (
                f"Could not start capture on interface '{self.interface}': {e}. "
                "Check the interface name via /api/interfaces."
            )
        except Exception as e:
            self.error = f"Capture stopped unexpectedly: {e}"
        finally:
            self.running = False

    def _process(self, packet):
        try:
            pkt_dict = self._extract(packet)
            if pkt_dict:
                self.on_packet(pkt_dict)
        except Exception:
            # a single malformed/unusual packet should never take the sniffer down
            pass

    @staticmethod
    def _extract(packet):
        if IP not in packet:
            return None
        ip_layer = packet[IP]
        info = {
            "timestamp": time.time(),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "size": len(packet),
            "src_port": None,
            "dst_port": None,
            "flags": None,
            "protocol": "Other",
        }
        if TCP in packet:
            tcp = packet[TCP]
            info["protocol"] = "TCP"
            info["src_port"] = int(tcp.sport)
            info["dst_port"] = int(tcp.dport)
            info["flags"] = str(tcp.flags)
        elif UDP in packet:
            udp = packet[UDP]
            info["protocol"] = "UDP"
            info["src_port"] = int(udp.sport)
            info["dst_port"] = int(udp.dport)
        elif ICMP in packet:
            info["protocol"] = "ICMP"
            info["flags"] = f"type={packet[ICMP].type}"
        return info
