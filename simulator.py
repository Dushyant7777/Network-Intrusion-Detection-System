"""
simulator.py
-------------
Synthetic traffic generator behind "Simulation Mode".

IMPORTANT: this module never touches the network in any way. It only
builds Python dicts shaped like the packet metadata Scapy capture would
produce, at randomized intervals, and hands them to the same callback
live capture uses. That keeps this project's demo path purely a data
generator -- it never crafts or sends real port scans, SYN floods, or
ICMP floods at anything, even for its own testing purposes. It exists so
the dashboard, database, and detection engine are fully exercisable
without root/administrator privileges or a live network to sniff.
"""

import random
import threading
import time

INTERNAL_HOSTS = [f"192.168.1.{i}" for i in (2, 5, 10, 14, 23, 42, 77, 101)]
EXTERNAL_HOSTS = [f"203.0.113.{i}" for i in range(1, 30)] + [f"198.51.100.{i}" for i in range(1, 30)]
ALL_HOSTS = INTERNAL_HOSTS + EXTERNAL_HOSTS

COMMON_TCP_PORTS = [80, 443, 22, 21, 3306, 8080, 25, 110]
COMMON_UDP_PORTS = [53, 123, 67, 68, 161]


class TrafficSimulator:
    def __init__(self, on_packet):
        self.on_packet = on_packet
        self._thread = None
        self._stop_flag = threading.Event()
        self.running = False
        self.error = None
        self.last_scenario = None

    def start(self):
        if self.running:
            return True
        self._stop_flag.clear()
        self.error = None
        self.last_scenario = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.running = True
        return True

    def stop(self):
        self._stop_flag.set()
        self.running = False

    # -- main loop -----------------------------------------------------

    def _run(self):
        next_attack_at = time.time() + random.uniform(12, 22)
        try:
            while not self._stop_flag.is_set():
                self._emit_normal_packet()
                if time.time() >= next_attack_at and not self._stop_flag.is_set():
                    self._run_random_attack_scenario()
                    next_attack_at = time.time() + random.uniform(25, 45)
                time.sleep(random.uniform(0.05, 0.2))
        except Exception as e:  # keep a broken generator from crashing the app
            self.error = str(e)
        finally:
            self.running = False

    # -- normal background traffic ---------------------------------------

    def _emit_normal_packet(self):
        protocol = random.choices(["TCP", "UDP", "ICMP", "Other"], weights=[60, 28, 8, 4])[0]
        src = random.choice(ALL_HOSTS)
        dst = random.choice(ALL_HOSTS)
        while dst == src:
            dst = random.choice(ALL_HOSTS)

        pkt = {
            "timestamp": time.time(),
            "src_ip": src,
            "dst_ip": dst,
            "protocol": protocol,
            "src_port": None,
            "dst_port": None,
            "size": random.randint(54, 1500),
            "flags": None,
        }
        if protocol == "TCP":
            pkt["src_port"] = random.randint(1024, 65535)
            pkt["dst_port"] = random.choice(COMMON_TCP_PORTS)
            pkt["flags"] = random.choices(["S", "SA", "A", "PA", "FA"], weights=[12, 15, 43, 25, 5])[0]
        elif protocol == "UDP":
            pkt["src_port"] = random.randint(1024, 65535)
            pkt["dst_port"] = random.choice(COMMON_UDP_PORTS)
        elif protocol == "ICMP":
            pkt["flags"] = "type=8"

        self.on_packet(pkt)

    # -- attack scenarios: synthetic data only, nothing ever sent anywhere --

    def _run_random_attack_scenario(self):
        scenario = random.choice(["port_scan", "syn_flood", "icmp_flood", "traffic_spike"])
        self.last_scenario = scenario
        getattr(self, f"_scenario_{scenario}")()

    def _scenario_port_scan(self):
        attacker, target = random.choice(EXTERNAL_HOSTS), random.choice(INTERNAL_HOSTS)
        for port in random.sample(range(1, 65000), k=random.randint(20, 40)):
            if self._stop_flag.is_set():
                return
            self.on_packet({
                "timestamp": time.time(), "src_ip": attacker, "dst_ip": target,
                "protocol": "TCP", "src_port": random.randint(1024, 65535),
                "dst_port": port, "size": random.randint(54, 60), "flags": "S",
            })
            time.sleep(random.uniform(0.02, 0.07))

    def _scenario_syn_flood(self):
        attacker, target = random.choice(EXTERNAL_HOSTS), random.choice(INTERNAL_HOSTS)
        port = random.choice([80, 443])
        for _ in range(random.randint(90, 180)):
            if self._stop_flag.is_set():
                return
            self.on_packet({
                "timestamp": time.time(), "src_ip": attacker, "dst_ip": target,
                "protocol": "TCP", "src_port": random.randint(1024, 65535),
                "dst_port": port, "size": random.randint(54, 60), "flags": "S",
            })
            time.sleep(random.uniform(0.01, 0.03))

    def _scenario_icmp_flood(self):
        attacker, target = random.choice(EXTERNAL_HOSTS), random.choice(INTERNAL_HOSTS)
        for _ in range(random.randint(90, 180)):
            if self._stop_flag.is_set():
                return
            self.on_packet({
                "timestamp": time.time(), "src_ip": attacker, "dst_ip": target,
                "protocol": "ICMP", "src_port": None, "dst_port": None,
                "size": random.randint(64, 128), "flags": "type=8",
            })
            time.sleep(random.uniform(0.01, 0.03))

    def _scenario_traffic_spike(self):
        for _ in range(random.randint(300, 500)):
            if self._stop_flag.is_set():
                return
            self._emit_normal_packet()
            time.sleep(random.uniform(0.002, 0.007))
