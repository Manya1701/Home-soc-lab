"""
detectors.py
Sliding-window anomaly detectors for the Home SOC Lab.

Each detector receives normalized packet events (dicts) one at a time via
`process(event)` and returns a list of alert dicts (empty if nothing fired).

Event schema (produced by capture.py / simulate_traffic.py):
{
    "timestamp": float (unix time),
    "src_ip": str,
    "dst_ip": str,
    "proto": "TCP" | "UDP" | "ICMP" | "OTHER",
    "dst_port": int | None,
    "flags": str | None,   # TCP flags, e.g. "S" for SYN
    "length": int,
}
"""

from collections import defaultdict, deque
import time


class PortScanDetector:
    """
    Flags a source IP as a likely port scanner if it touches more than
    `port_threshold` distinct destination ports within `window_seconds`.
    Classic behavioral signature of Nmap-style scans.
    """

    def __init__(self, window_seconds: int = 10, port_threshold: int = 15):
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        # src_ip -> deque[(timestamp, dst_port)]
        self._history = defaultdict(deque)
        self._already_alerted = set()

    def process(self, event: dict) -> list:
        alerts = []
        if event["proto"] != "TCP" or event["dst_port"] is None:
            return alerts
        # Only SYN packets (no ACK) are the classic scan signature
        if event.get("flags") and "S" in event["flags"] and "A" not in event["flags"]:
            src = event["src_ip"]
            hist = self._history[src]
            hist.append((event["timestamp"], event["dst_port"]))

            # drop entries outside the window
            cutoff = event["timestamp"] - self.window_seconds
            while hist and hist[0][0] < cutoff:
                hist.popleft()

            distinct_ports = {p for _, p in hist}
            if len(distinct_ports) >= self.port_threshold:
                # avoid re-alerting every single packet once threshold is crossed
                alert_key = (src, event["timestamp"] // self.window_seconds)
                if alert_key not in self._already_alerted:
                    self._already_alerted.add(alert_key)
                    alerts.append({
                        "timestamp": event["timestamp"],
                        "type": "PORT_SCAN",
                        "severity": "HIGH",
                        "src_ip": src,
                        "detail": f"{len(distinct_ports)} distinct ports in "
                                  f"{self.window_seconds}s window",
                    })
        return alerts


class IcmpFloodDetector:
    """
    Flags an ICMP flood (basic ping-flood / recon sweep signature) when a
    single source sends more than `count_threshold` ICMP packets within
    `window_seconds`.
    """

    def __init__(self, window_seconds: int = 5, count_threshold: int = 30):
        self.window_seconds = window_seconds
        self.count_threshold = count_threshold
        self._history = defaultdict(deque)
        self._already_alerted = set()

    def process(self, event: dict) -> list:
        alerts = []
        if event["proto"] != "ICMP":
            return alerts

        src = event["src_ip"]
        hist = self._history[src]
        hist.append(event["timestamp"])

        cutoff = event["timestamp"] - self.window_seconds
        while hist and hist[0] < cutoff:
            hist.popleft()

        if len(hist) >= self.count_threshold:
            alert_key = (src, event["timestamp"] // self.window_seconds)
            if alert_key not in self._already_alerted:
                self._already_alerted.add(alert_key)
                alerts.append({
                    "timestamp": event["timestamp"],
                    "type": "ICMP_FLOOD",
                    "severity": "MEDIUM",
                    "src_ip": src,
                    "detail": f"{len(hist)} ICMP packets in "
                              f"{self.window_seconds}s window",
                })
        return alerts


class TrafficSpikeDetector:
    """
    Flags a source IP whose overall packet rate (any protocol) spikes above
    `packet_threshold` packets within `window_seconds`. Catches generic
    volumetric anomalies that the other two detectors might miss.
    """

    def __init__(self, window_seconds: int = 5, packet_threshold: int = 100):
        self.window_seconds = window_seconds
        self.packet_threshold = packet_threshold
        self._history = defaultdict(deque)
        self._already_alerted = set()

    def process(self, event: dict) -> list:
        alerts = []
        src = event["src_ip"]
        hist = self._history[src]
        hist.append(event["timestamp"])

        cutoff = event["timestamp"] - self.window_seconds
        while hist and hist[0] < cutoff:
            hist.popleft()

        if len(hist) >= self.packet_threshold:
            alert_key = (src, event["timestamp"] // self.window_seconds)
            if alert_key not in self._already_alerted:
                self._already_alerted.add(alert_key)
                alerts.append({
                    "timestamp": event["timestamp"],
                    "type": "TRAFFIC_SPIKE",
                    "severity": "LOW",
                    "src_ip": src,
                    "detail": f"{len(hist)} packets in "
                              f"{self.window_seconds}s window",
                })
        return alerts


class DetectorEngine:
    """Runs every registered detector against each incoming event."""

    def __init__(self):
        self.detectors = [
            PortScanDetector(),
            IcmpFloodDetector(),
            TrafficSpikeDetector(),
        ]

    def process(self, event: dict) -> list:
        all_alerts = []
        for d in self.detectors:
            all_alerts.extend(d.process(event))
        return all_alerts
