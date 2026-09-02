"""
simulate_traffic.py
Feeds synthetic traffic through the exact same DetectorEngine + SocLogger
pipeline that capture.py uses on live traffic — no root, no real network
needed. Useful for demos, testing, and generating sample data for
report.py without touching real interfaces.

Simulates three scenarios back to back:
  1. Normal background traffic (baseline noise)
  2. A port scan from a single attacker IP
  3. An ICMP flood from a second attacker IP

Run: python3 simulate_traffic.py
"""

import random
import time

from detectors import DetectorEngine
from logger import SocLogger

NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
COMMON_PORTS = [80, 443, 53, 22, 3389]
ATTACKER_SCAN_IP = "10.0.0.66"
ATTACKER_FLOOD_IP = "10.0.0.77"
TARGET_IP = "192.168.1.1"


def make_event(t, src, dst, proto, dst_port=None, flags=None, length=64):
    return {
        "timestamp": t,
        "src_ip": src,
        "dst_ip": dst,
        "proto": proto,
        "dst_port": dst_port,
        "flags": flags,
        "length": length,
    }


def generate_normal_traffic(start_t, n=40):
    events = []
    t = start_t
    for _ in range(n):
        t += random.uniform(0.05, 0.3)
        src = random.choice(NORMAL_IPS)
        proto = random.choice(["TCP", "UDP"])
        port = random.choice(COMMON_PORTS)
        flags = "SA" if proto == "TCP" else None  # established-looking traffic
        events.append(make_event(t, src, TARGET_IP, proto, port, flags))
    return events, t


def generate_port_scan(start_t, n=25):
    """Single attacker hitting many distinct ports with bare SYNs."""
    events = []
    t = start_t
    for i in range(n):
        t += 0.05  # fast, bursty — classic scan timing
        port = 1000 + i  # distinct port each time
        events.append(make_event(t, ATTACKER_SCAN_IP, TARGET_IP, "TCP", port, flags="S"))
    return events, t


def generate_icmp_flood(start_t, n=40):
    events = []
    t = start_t
    for _ in range(n):
        t += 0.05
        events.append(make_event(t, ATTACKER_FLOOD_IP, TARGET_IP, "ICMP"))
    return events, t


def main():
    engine = DetectorEngine()
    soc_logger = SocLogger()

    t = time.time()
    all_events = []

    print("Simulating background traffic...")
    ev, t = generate_normal_traffic(t)
    all_events += ev

    print("Simulating a port scan attack...")
    ev, t = generate_port_scan(t)
    all_events += ev

    print("Simulating more background traffic...")
    ev, t = generate_normal_traffic(t)
    all_events += ev

    print("Simulating an ICMP flood attack...\n")
    ev, t = generate_icmp_flood(t)
    all_events += ev

    for event in all_events:
        soc_logger.log_packet(event)
        for alert in engine.process(event):
            soc_logger.log_alert(alert)

    soc_logger.close()


if __name__ == "__main__":
    main()
