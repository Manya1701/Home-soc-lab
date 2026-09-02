"""
capture.py
Live traffic capture entry point for the Home SOC Lab.

Requires: Linux (e.g. Kali), Scapy, and root privileges (raw sockets).
Run:  sudo python3 capture.py --iface eth0
      sudo python3 capture.py --iface wlan0 --duration 120

This is the "real" half of the project — it sniffs live packets off the
given interface, normalizes each one into the event schema documented in
detectors.py, runs it through the DetectorEngine, and logs everything via
SocLogger. If you don't have root/a spare interface to test on right now,
use simulate_traffic.py instead — it exercises the exact same detection
and logging pipeline using synthetically crafted packets, no root needed.
"""

import argparse
import time

from scapy.all import sniff, IP, TCP, UDP, ICMP

from detectors import DetectorEngine
from logger import SocLogger


def normalize_packet(pkt) -> dict | None:
    """Convert a raw Scapy packet into our flat event dict. Returns None
    for anything without an IP layer (nothing to analyze)."""
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    event = {
        "timestamp": time.time(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "proto": "OTHER",
        "dst_port": None,
        "flags": None,
        "length": len(pkt),
    }

    if pkt.haslayer(TCP):
        event["proto"] = "TCP"
        event["dst_port"] = int(pkt[TCP].dport)
        event["flags"] = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        event["proto"] = "UDP"
        event["dst_port"] = int(pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        event["proto"] = "ICMP"

    return event


def main():
    parser = argparse.ArgumentParser(description="Home SOC Lab - live capture")
    parser.add_argument("--iface", default=None, help="Network interface to sniff (e.g. eth0)")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds")
    args = parser.parse_args()

    engine = DetectorEngine()
    soc_logger = SocLogger()

    print(f"Starting capture on iface={args.iface or 'default'} "
          f"for {args.duration}s. Press Ctrl+C to stop early.\n")

    def handle_packet(pkt):
        event = normalize_packet(pkt)
        if event is None:
            return
        soc_logger.log_packet(event)
        for alert in engine.process(event):
            soc_logger.log_alert(alert)

    try:
        sniff(iface=args.iface, prn=handle_packet, store=False, timeout=args.duration)
    except PermissionError:
        print("Permission denied: this script needs raw-socket access. "
              "Re-run with sudo.")
    except KeyboardInterrupt:
        pass
    finally:
        soc_logger.close()


if __name__ == "__main__":
    main()
